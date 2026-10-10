// ============================================================================
// variableResolver.service.ts — hierarchical TEMPLATE VARIABLES
// ============================================================================
//
// This is the PORT of `services/settings.service.ts` to template variables.
// Three properties of that file were audited, corrected and hardened on this
// project; they are reproduced here verbatim in intent, because relearning them
// on the config-push path would cost a customer network:
//
//   1. `tenantId` is the FIRST parameter of every function and has NO default.
//      A caller that forgets it must fail to COMPILE, not fall back silently on
//      the master tenant.
//   2. The ancestor walk joins `device_groups` and filters on `tenant_id`.
//      A cross-tenant closure edge must not make one customer's
//      routers inherit another customer's variables.
//   3. The chain is resolved in ONE query ordered by decreasing depth, never in
//      N+1 round-trips. Here it is literally one query: the
//      six stored levels (instance, global, tenant, group, site, device — the
//      site since migration 035, the instance since 038) are UNION-ed in SQL,
//      and ranked by `VARIABLE_SCOPE_RANK`.
//
// THE INSTANCE LEVEL (migration 038) is the one exception to "every row is a
// tenant's": a value shared by every tenant of the installation (the
// management L2TP password, the SNMP community), stored with a NULL
// `tenant_id`, below `global` — which, despite its name, is one tenant's
// widest level. Every tenant's chain reads it; only a platform administrator
// writes it (`setInstance`, behind `requireRole('admin')`).
//
// TWO LEVELS ARE DECLARED BUT NEVER STORED (`RENDER_TIME_LEVELS`): `computed`
// (supplied by ObliWAN at render time — the allocator's outputs) and `bench`
// (typed at the provisioning bench for one box). The caller of a render hands
// them in (`RenderTimeValues`); for a key a revision declares at one of them,
// ONLY that map counts — a stored row of the same name is set aside and
// reported in `shadowed`, never rendered — and a required one that was not
// supplied refuses the render, naming it (`applyRenderTimeValues`). Two
// callers: the bench compile (site path), and the fleet render of a
// bench-prepared router (device path, `render.service`), which holds the
// allocation's values and the box facts but none of the render-time SECRETS —
// those it declares `withheld`, and they render as placeholders only.
//
// WHAT DIFFERS FROM `settings`, and why this file is not a copy-paste:
//
//   - a variable is TYPED. A `var_schema` (JSON Schema) carried by the template
//     revision declares each variable, its type, its default and whether it is
//     required. Validation is `ajv` + `ajv-formats`.
//   - a variable can be REQUIRED WITHOUT A DEFAULT. A device for which it does
//     not resolve must NOT produce a render with a hole in it: it produces a
//     `VariableResolutionError` naming the variable, the device, and the level
//     at which it should have been defined. A silently incomplete config that
//     reaches a router is precisely what this product exists to prevent.
//   - a variable can be SECRET. Its value lives in the vault; the secrets rule says it
//     exists IN MEMORY ONLY on the path vault -> equipment. It must never
//     appear in a stored render, a diff, a plan, the UI, an export or a LOG.
//     Everything that is not that one path gets the REDACTED form.
//   - every value carries its ORIGIN (Default / Instance / Global / Tenant /
//     Group X / Site / Device, or Computed by ObliWAN / Typed at the bench) — the shape `{ value, source, sourceId, sourceName }` is
//     what the existing `client/src/components/settings/InheritanceBadge.tsx`
//     reads.
//   - a variable can be resolved for a router that does NOT EXIST yet.
//     `resolveForSite()` walks instance -> global -> tenant -> group -> site for the
//     provisioning bench, where the box on the table has no `devices` row and
//     the site is the only identity it will have until it is enrolled.
//
// TEMPLATE CODE EXECUTION — this file feeds the Nunjucks worker. `buildRenderContext()` is the
// ONLY producer of a template context, and what it returns has been proved to
// be PURE JSON: no live object, no function, no inherited prototype, no
// `__proto__` / `constructor` / `prototype` key. Nothing that could carry
// `{{ x.constructor.constructor('...')() }}` across the worker boundary comes
// from here. The worker itself, its `resourceLimits` and its 5 s timeout are
// the other half of the mitigation and live in `renderWorker.ts`.
//
// ---------------------------------------------------------------------------
// TABLE THIS SERVICE READS — `config_variables`, migration 008.
// Its decision 6 splits the storage in two columns and makes it a CHECK:
//
//     is_secret = false  ->  value IS NOT NULL, secret_enc IS NULL
//     is_secret = true   ->  value IS NULL,     secret_enc IS NOT NULL
//
// That is a better boundary than a marker object inside `value`, because "a
// secret ended up in a jsonb column that gets rendered, diffed and exported"
// stops being a code review question and becomes an impossible row. This file
// reads and writes exactly that shape, and treats any row that contradicts it
// as REJECTED rather than as data.
//
// `settings`-style uniqueness applies: two PARTIAL unique
// indexes, `(tenant_id, scope, key) WHERE scope_id IS NULL` and
// `(tenant_id, scope, scope_id, key) WHERE scope_id IS NOT NULL`, because a
// naive `UNIQUE(scope,scope_id,key)` constrains NOTHING at the two levels that
// apply to a whole fleet (PostgreSQL 16 is still NULLS DISTINCT). The upserts
// below target them through their conflict EXPRESSION, WHERE clause included —
// PostgreSQL cannot infer a partial index from a bare column list, and the
// expression form does not couple this file to 008's index names. A `site` row
// (migration 035) has a non-NULL `scope_id` and `scope` is part of the key, so
// the second index already covers it; 035 adds no index of its own.
// ============================================================================

import crypto from 'crypto';
import type { Knex } from 'knex';
import Ajv, { type ValidateFunction } from 'ajv';
import addFormats from 'ajv-formats';
import { LRUCache } from 'lru-cache';
import type { SecretFingerprint } from '@obliwan/shared';
import { db } from '../../db';
import { config } from '../../config';
import { decrypt, encrypt } from '../secretVault.service';
import {
  CONTEXT_FACT_KEYS, INSTANCE_SCOPE, RENDER_TIME_LEVELS, RESERVED_FACT_KEYS,
  SECRET_PLACEHOLDER_RE, STORED_VARIABLE_SCOPES, VARIABLE_KEY_RE, VARIABLE_LEVELS,
  VARIABLE_SCOPES, isContextFactKey,
} from '../../validators/template.schema';

// The naming rule, the placeholder shape and the level lists live at the API
// boundary (`validators/template.schema.ts`) so that a form field — or the
// engine's output lint — can use them without importing a module that opens a
// database connection. They are re-exported here because this service is where
// the rest of the template engine (and the push path's `secrets.ts`) looks for them, and because
// there must be exactly one regex.
export {
  CONTEXT_FACT_KEYS, INSTANCE_SCOPE, RENDER_TIME_LEVELS, RESERVED_FACT_KEYS,
  SECRET_PLACEHOLDER_RE, STORED_VARIABLE_SCOPES, VARIABLE_KEY_RE, VARIABLE_LEVELS,
  VARIABLE_SCOPES,
};

// ============================================================================
// Types
// ============================================================================

/** The five levels a TENANT stores values at, narrowest last — what the
 *  tenant-scoped variables routes accept. */
export type VariableScope = (typeof VARIABLE_SCOPES)[number];

/** Every level a row can be stored at: the tenant's five plus `instance`. */
export type StoredVariableScope = (typeof STORED_VARIABLE_SCOPES)[number];

/** The two levels supplied by the caller of a render, never stored. */
export type RenderTimeLevel = (typeof RENDER_TIME_LEVELS)[number];

/** Anything `x-obliwan-level` may say. */
export type VariableLevel = (typeof VARIABLE_LEVELS)[number];

/** Where a resolved value came from. `'default'` = the `var_schema` default. */
export type VariableSource = VariableLevel | 'default';

/**
 * THE precedence rule, as numbers: a higher rank overrides a lower one.
 *
 *   instance (-1) < global (0) < tenant (1) < group (2, farthest ancestor
 *   first) < site (3) < device (4)
 *
 * The instance level is below every level a tenant owns: a fleet-wide value is
 * a default the platform offers, and a tenant that sets the same key anywhere
 * in its own chain overrides it for its own routers only.
 *
 * A site value beats every group, whatever the group's depth: a group states a
 * fleet-wide POLICY ("our branches use VLAN 10"), a site states a FACT about
 * one premises ("this branch is on VLAN 835"), and the fact must win. A device
 * override still beats the site — it is the escape hatch for the one router
 * that must differ from its own premises.
 *
 * `computed` and `bench` have no rank: they are not stored, so they never meet
 * a stored row in this ordering. A key a revision declares at one of them is
 * taken from the caller's map and from nothing else (`applyRenderTimeValues`).
 *
 * Written ONCE. The chain query interpolates these numbers into its SQL, and
 * `chainRows` re-sorts what comes back with `compareChainOrder` below, so the
 * order a fold sees is decided by TypeScript a harness can run without a
 * database — the SQL `ORDER BY` is the same rule, not a second one.
 */
export const VARIABLE_SCOPE_RANK: Readonly<Record<StoredVariableScope, number>> = Object.freeze({
  instance: -1,
  global: 0,
  tenant: 1,
  group: 2,
  site: 3,
  device: 4,
});

/**
 * `ORDER BY rank ASC, depth DESC NULLS LAST`, in TypeScript.
 *
 * Lower rank first, so a left-to-right fold lets the narrower level overwrite
 * the wider one. Within the group rank, the FARTHEST ancestor first (largest
 * closure depth) and the device's own group (depth 0) last — the ordering
 * `settings.service._ancestorOverrides` uses, for the same reason. `depth` is
 * NULL on every other level, and each of those contributes at most one row per
 * key, so NULLS LAST only ever breaks ties that cannot carry the same key.
 */
export function compareChainOrder(
  a: { scope: StoredVariableScope; depth: number | null },
  b: { scope: StoredVariableScope; depth: number | null },
): number {
  const byRank = VARIABLE_SCOPE_RANK[a.scope] - VARIABLE_SCOPE_RANK[b.scope];
  if (byRank !== 0) return byRank;
  if (a.depth === b.depth) return 0;
  if (a.depth === null) return 1;
  if (b.depth === null) return -1;
  return b.depth - a.depth;
}

/** JSON, and nothing but JSON. `undefined` is deliberately absent from this
 *  union: it does not survive `JSON.stringify`, and it is the single most
 *  common way a hole reaches a router. */
export type JsonValue =
  | null
  | boolean
  | number
  | string
  | JsonValue[]
  | { [k: string]: JsonValue };

/**
 * One resolved variable, in its REDACTED form — safe for `config_renders`, the
 * diff, the plan, the UI, an export and a log line.
 *
 * The `{ value, source, sourceId, sourceName }` quartet is deliberately the
 * same shape as `SettingValue` in `@obliwan/shared`, so `InheritanceBadge`
 * renders it unchanged. (That component has a branch for 'default' and for
 * each of the tenant's five levels; for `source: 'instance'`, 'computed' or
 * 'bench' it renders nothing — a client change, outside this file's
 * perimeter, listed in the hand-off.)
 */
export interface ResolvedVariable {
  key: string;
  /** Redacted when `isSecret`: never the plaintext. */
  value: JsonValue;
  source: VariableSource;
  sourceId: number | null;
  sourceName: string;
  /** Closure depth of the winning group (0 = the device's own group), else null. */
  sourceDepth: number | null;
  isSecret: boolean;
  /** true when `value` is the placeholder rather than the real value. */
  redacted: boolean;
  /**
   * Keyed fingerprint of the plaintext, per tenant, so "the secret changed" is
   * detectable without the platform ever writing the secret to a diffable
   * store. Same construction as `SecretFingerprint` in the NCM contract.
   * `null` for a non-secret variable, and for a render-time secret the render
   * does not hold (`RenderTimeValues.withheld`): nothing is known of its value.
   */
  fingerprint: SecretFingerprint | null;
}

export type ResolvedVariables = Record<string, ResolvedVariable>;

/** One step of the chain that was actually searched, for error messages. */
export interface ChainStep {
  scope: StoredVariableScope;
  scopeId: number | null;
  label: string;
  depth: number | null;
}

export interface MissingVariable {
  key: string;
  /** Level the template author declared with `x-obliwan-level`, else 'device'
   *  — and 'site' wherever that would say 'device' for a bench target, which
   *  has no device level to define anything at (see `buildReport`). A
   *  `computed` or `bench` level means the CALLER of the render did not
   *  supply it: nothing stored can satisfy it. */
  expectedScope: VariableLevel;
  reason: 'required-and-unresolved' | 'secret-declared-but-absent';
}

/** A stored row set aside because the revision declares its key at a
 *  render-time level: only the caller's map may supply that key. Reported so
 *  "why is my site value not rendered" has an answer. */
export interface ShadowedVariable {
  key: string;
  /** The level the revision declares the key at. */
  declaredLevel: RenderTimeLevel;
  /** Where the stored value that was set aside came from. */
  storedAt: VariableSource;
  storedAtName: string;
}

export interface VariableTypeError {
  key: string;
  /** ajv's message, or ours. NEVER contains the offending value: a secret must
   *  not reach a log through a validation error. */
  message: string;
  source: VariableSource;
  sourceName: string;
}

/** A row the API could not have written — a key that does not match
 *  `VARIABLE_KEY_RE`, or a broken secret envelope. Skipped, never rendered,
 *  always reported. */
export interface RejectedVariable {
  key: string;
  scope: StoredVariableScope;
  scopeId: number | null;
  reason: string;
}

/** The full picture for one target. Non-throwing: this is the INSPECTION view
 *  (variables UI, template preview). `buildRenderContext()` is the throwing one.
 *
 *  The target is either a device (`deviceId` set, its site read from its own
 *  `devices.site_id`) or, on the bench path, a site with no device yet
 *  (`deviceId` and `deviceName` null, `siteId` set). */
export interface VariableReport {
  tenantId: number;
  deviceId: number | null;
  deviceName: string | null;
  groupId: number | null;
  /** The site whose values took part in the chain, null when there is none —
   *  a device not filed under a site, or a group / tenant view. Only a site of
   *  THIS tenant is ever reported here. */
  siteId: number | null;
  siteName: string | null;
  chain: ChainStep[];
  variables: ResolvedVariables;
  missing: MissingVariable[];
  typeErrors: VariableTypeError[];
  rejected: RejectedVariable[];
  /** Stored rows set aside for a render-time declaration. Informative, never
   *  a reason to refuse. */
  shadowed: ShadowedVariable[];
  /** Keys of the caller's `computed` map the revision does not declare
   *  `computed` — not rendered. The allocator hands in everything it knows;
   *  a revision takes what it declares. */
  unusedComputed: string[];
  /** true when a render may proceed. */
  ok: boolean;
}

/** What `buildRenderContext()` hands to the render worker. */
export interface RenderContext {
  /** PURE JSON. In `'redacted'` mode secrets are placeholders; in `'secrets'`
   *  mode they are plaintext and this object is IN-MEMORY ONLY. */
  context: Record<string, JsonValue>;
  mode: 'redacted' | 'secrets';
  /** Redacted view — this is the one that goes into `variables_snapshot`. */
  variables: ResolvedVariables;
  /** Keys whose value is a secret, in either mode. */
  secretKeys: string[];
  report: VariableReport;
}

// ============================================================================
// Errors
// ============================================================================

/**
 * Raised instead of rendering a hole. Carries the machine-readable lists so a
 * controller can turn it into a 422 with a per-variable form error, and a
 * message an operator can act on without opening a log aggregator.
 */
export class VariableResolutionError extends Error {
  constructor(
    message: string,
    readonly tenantId: number,
    readonly deviceId: number | null,
    readonly missing: MissingVariable[],
    readonly typeErrors: VariableTypeError[],
    readonly chain: ChainStep[],
    /** The target's site, when it has one — and the ONLY identity of a bench
     *  target, whose `deviceId` is null. */
    readonly siteId: number | null = null,
  ) {
    super(message);
    this.name = 'VariableResolutionError';
  }
}

/** The `var_schema` of the revision is not a usable JSON Schema. */
export class VarSchemaError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'VarSchemaError';
  }
}

/**
 * A site form (`setSiteValues`) was refused as a whole. Every entry that could
 * not be written is listed with its KEY and a reason — never with its value, a
 * secret included, so the list is safe to return to the caller verbatim.
 */
export class SiteVariablesRefusedError extends Error {
  constructor(readonly errors: SiteValueError[]) {
    super(
      `Site variables refused, nothing was written: ${errors
        .map((e) => `"${e.key}" ${e.message}`)
        .join('; ')}. Correct the listed values and send the form again.`,
    );
    this.name = 'SiteVariablesRefusedError';
  }
}

/** A value crossing into the render worker was not pure JSON. */
export class ImpureContextError extends Error {
  constructor(
    message: string,
    readonly path: string,
  ) {
    super(message);
    this.name = 'ImpureContextError';
  }
}

// ============================================================================
// Key naming — the first line of defence against prototype pollution
// ============================================================================

// `VARIABLE_KEY_RE` is imported from the validator above and mirrors migration
// 008's `config_variables_key_chk` exactly. Its leading-lowercase-letter rule
// makes `__proto__` unrepresentable — but NOT `constructor` and NOT
// `prototype`, which match it. 008's header claims otherwise; that claim is
// wrong. The set below is what actually stops
// those two, and it is applied at write time (`assertWritable`), at read time
// (`fold` — a row inserted by psql behind the API's back is rejected, not
// rendered) and again on the whole context before it crosses into the worker
// (`assertJsonPure`). Three checks for one rule, because the cost of the rule
// failing is a Nunjucks context whose prototype an attacker controls.
const FORBIDDEN_KEYS = new Set(['__proto__', 'constructor', 'prototype']);

// ============================================================================
// Redaction
// ============================================================================

/**
 * The masked form of a secret. It names the VARIABLE, not the value: the key is
 * already public (it is declared in `var_schema`, which the operator wrote),
 * and a reviewer reading a masked plan needs to know WHICH secret lands where.
 *
 * A constant per key also makes the masked body byte-stable across a secret
 * ROTATION — deliberately: the masked artefact must not be a rotation oracle.
 * "The secret changed" is carried by `ResolvedVariable.fingerprint`, which is
 * keyed per tenant and irreversible.
 */
export function redactedPlaceholder(key: string): string {
  return `__OBLIWAN_SECRET_${key.toUpperCase()}__`;
}

// `SECRET_PLACEHOLDER_RE` — the shape of what `redactedPlaceholder` returns —
// is defined in `validators/template.schema.ts` and re-exported at the top of
// this file.

/**
 * Refuse a string that contains a secret plaintext, of any length, as a bare
 * substring. The error names the variable and never echoes the value.
 *
 * NOT the check a render runs: a template's output legitimately carries short
 * numbers and codes that contain a short secret by coincidence (a PIN inside a
 * store code), and this rule cannot tell those apart from a leak. A render runs
 * `assertNoStoredSecretInRender` below, which can.
 */
export function assertNoPlaintextSecret(
  subject: string,
  secrets: readonly { key: string; plaintext: string }[],
  what = 'value',
): void {
  for (const s of secrets) {
    if (s.plaintext.length > 0 && subject.includes(s.plaintext)) {
      throw new Error(
        `Refusing to persist ${what}: it contains the plaintext of the secret ` +
          `variable "${s.key}" (a secret exists in memory ` +
          'only, on the path vault -> device).',
      );
    }
  }
}

/**
 * Below this many characters a stored secret is looked for as a whole TOKEN —
 * an occurrence not flanked by an ASCII letter, digit or underscore — rather
 * than as a bare substring. A SIM PIN is four digits and a store code five: as a substring, a
 * PIN made of zeros sits inside "00001", "00004", "00007"…, and the bare
 * substring scan refused every such store with an error claiming a credential
 * had been typed into the template (six of the seven converted operator
 * templates, on real store codes). From eight characters up, a coincidental
 * substring stops being the likely explanation and the bare rule applies.
 */
export const SHORT_SECRET_LENGTH = 8;

const WORD_CHAR = /[A-Za-z0-9_]/;

/** Does `plaintext` occur in `text`, by the rule above? Exported for the
 *  harness. An empty plaintext never occurs. */
export function plaintextOccursIn(text: string, plaintext: string): boolean {
  if (plaintext.length === 0) return false;
  if (plaintext.length >= SHORT_SECRET_LENGTH) return text.includes(plaintext);
  for (let i = text.indexOf(plaintext); i >= 0; i = text.indexOf(plaintext, i + 1)) {
    const before = i > 0 ? text.charAt(i - 1) : '';
    const after = text.charAt(i + plaintext.length);
    if (!WORD_CHAR.test(before) && !WORD_CHAR.test(after)) return true;
  }
  return false;
}

/** Every string and number of a render context, with the path it sits at —
 *  the values the template was handed IN CLEAR. The context is the REDACTED
 *  one, where a secret is only ever its placeholder. */
function clearLeaves(value: unknown, path: string, out: { path: string; text: string }[]): void {
  if (typeof value === 'string') {
    out.push({ path, text: value });
  } else if (typeof value === 'number') {
    out.push({ path, text: String(value) });
  } else if (Array.isArray(value)) {
    value.forEach((v, i) => clearLeaves(v, `${path}[${i}]`, out));
  } else if (value !== null && typeof value === 'object') {
    for (const k of Object.keys(value)) {
      clearLeaves((value as Record<string, unknown>)[k], path ? `${path}.${k}` : k, out);
    }
  }
}

/**
 * The secrets rule on a render, before anything derived from it is kept or shipped: refuse
 * a STORED secret's plaintext that reached the template or its output. Run by
 * every render path — the device render, the scratch preview, the bench.
 *
 * The render context is REDACTED, so no variable can carry a plaintext into
 * the output. Three things can, and each is judged where it means what the
 * error says:
 *
 *  1. THE TEMPLATE TEXT — an author typed a credential into the body or a
 *     partial. Judged on `sources` themselves, for every stored secret of the
 *     chain, shadowed ones included: a credential in a revision is in clear in
 *     the database whatever this render does with its key.
 *  2. A VALUE HANDED TO THE TEMPLATE IN CLEAR — a stored non-secret variable, a
 *     computed or non-secret bench value, a fact (`site.code`, `device.serial`)
 *     — that contains it. For a secret of `SHORT_SECRET_LENGTH` or more that is
 *     the credential stored a second time, outside the vault: refused, naming
 *     the value. For a shorter one it is what a four-digit PIN inside a
 *     five-digit store code looks like, and the render goes on — the value was
 *     stored or supplied in clear on purpose, and the render discloses nothing
 *     that value did not already.
 *  3. NEITHER — the template assembled it (`"pass" ~ "word"`, arithmetic).
 *
 * Only STORED secrets (`loadSecrets`, `loadSecretsForSite`). A bench or
 * computed secret is typed or generated for one box after the template was
 * written; the text cannot carry it except by coincidence.
 *
 * Messages name the variable, the source or the context path — never a value.
 */
export function assertNoStoredSecretInRender(opts: {
  /** Loader name -> template source: the body and every partial rendered. */
  sources: Readonly<Record<string, string>>;
  /** The rendered text, REDACTED. */
  output: string;
  /** The REDACTED context the output was rendered from. */
  context: unknown;
  secrets: readonly { key: string; plaintext: string }[];
  /** "this render", "this preview", "this bench render". */
  what: string;
}): void {
  let leaves: { path: string; text: string }[] | null = null;
  for (const s of opts.secrets) {
    if (s.plaintext.length === 0) continue;
    for (const name of Object.keys(opts.sources)) {
      if (plaintextOccursIn(opts.sources[name], s.plaintext)) {
        throw new Error(
          `Refusing ${opts.what}: the template text ("${name}") contains the plaintext of the ` +
            `secret variable "${s.key}". A credential typed into a template is stored in clear ` +
            'with the revision and copied into every render of it — ' +
            'reference the variable instead.',
        );
      }
    }
    if (!plaintextOccursIn(opts.output, s.plaintext)) continue;
    if (leaves === null) {
      leaves = [];
      clearLeaves(opts.context, '', leaves);
    }
    const carrier = leaves.find((l) => l.text.includes(s.plaintext));
    if (carrier && s.plaintext.length < SHORT_SECRET_LENGTH) continue;
    throw new Error(
      carrier
        ? `Refusing ${opts.what}: the value "${carrier.path}", handed to the template in clear, ` +
            `contains the plaintext of the secret variable "${s.key}" — the same credential ` +
            'stored a second time, outside the vault. Store it as a ' +
            `secret, or reference "${s.key}".`
        : `Refusing ${opts.what}: the rendered text contains the plaintext of the secret ` +
            `variable "${s.key}", although neither the template text nor any value handed to ` +
            'it in clear carries it — the template assembles it.',
    );
  }
}

// ============================================================================
// Vault blob shape
// ============================================================================

/**
 * `secretVault`'s storage format: `v1:<key_version>:<iv>:<tag>:<ciphertext>`.
 * Used only to notice a blob that has been pasted into the CLEAR `value`
 * column — a row that migration 008's CHECK permits (it is a legal non-secret
 * string) but that means somebody stored a credential on the rendered path.
 */
const VAULT_BLOB_RE = /^v1:\d+:[A-Za-z0-9+/=]+:[A-Za-z0-9+/=]+:[A-Za-z0-9+/=]*$/;

// ============================================================================
// Secret fingerprint — same construction as the NCM `SecretFingerprint`
// ============================================================================

const FP_UNAVAILABLE: SecretFingerprint = {
  algo: 'hmac-sha256/v1',
  fp: null,
  unavailable: true,
};

/**
 * Per-tenant key derived from OBLIWAN_ENCRYPTION_KEY, so two tenants using the
 * same weak PSK are not linkable through a stored fingerprint. Derivation only
 * — the key never leaves this module and is never persisted.
 */
function tenantFingerprintKey(tenantId: number): Buffer | null {
  if (!config.encryptionKey || !config.encryptionKeyValid) return null;
  return crypto
    .createHmac('sha256', Buffer.from(config.encryptionKey.trim(), 'hex'))
    .update(`obliwan:varfp:v1:${tenantId}`)
    .digest();
}

/**
 * Learning mode: the fingerprint of a secret read off a router, over the VALUE
 * only (no key, no menu), with the tenant's own HMAC key — so equal secrets on
 * two sites of one workspace compare equal, and never across workspaces.
 * Null when the vault key is unavailable. A key rotation breaks equality
 * between fingerprints taken before and after it.
 */
export function learnedSecretFingerprint(tenantId: number, plaintext: string): string | null {
  const k = tenantFingerprintKey(tenantId);
  if (!k) return null;
  return crypto.createHmac('sha256', k).update(`learned|${plaintext}`).digest().toString('base64url').slice(0, 22);
}

function fingerprintSecret(tenantId: number, key: string, plaintext: string): SecretFingerprint {
  const k = tenantFingerprintKey(tenantId);
  if (!k) return FP_UNAVAILABLE;
  const mac = crypto.createHmac('sha256', k).update(`configVar|${key}|${plaintext}`).digest();
  return {
    algo: 'hmac-sha256/v1',
    fp: mac.toString('base64url').slice(0, 22),
    unavailable: false,
  };
}

// ============================================================================
// JSON purity — the template-execution boundary
// ============================================================================

const MAX_CONTEXT_DEPTH = 32;

/**
 * Prove a value is pure JSON, or throw naming the exact path.
 *
 * What this rejects, and why each one matters at the worker boundary:
 *   undefined / function / symbol / bigint — not JSON; a function is a
 *       reachable callable inside the sandbox.
 *   NaN / Infinity — `JSON.stringify` turns them into `null`, i.e. a silent
 *       hole in a router configuration.
 *   a non-plain object (Date, Buffer, Map, a class instance) — carries a
 *       prototype, and a prototype carries `constructor`, which is step one of
 *       `{{ x.constructor.constructor('...')() }}`.
 *   `__proto__` / `constructor` / `prototype` as a KEY — prototype pollution.
 *   an accessor property — a getter is a function call in disguise.
 *   a cycle, or depth > 32 — a hostile or accidental structure that would hang
 *       the serializer.
 */
export function assertJsonPure(
  value: unknown,
  path = '$',
  seen: Set<unknown> = new Set<unknown>(),
  depth = 0,
): void {
  if (depth > MAX_CONTEXT_DEPTH) {
    throw new ImpureContextError(
      `Context is deeper than ${MAX_CONTEXT_DEPTH} levels at ${path}.`,
      path,
    );
  }
  if (value === null) return;

  const t = typeof value;
  if (t === 'string' || t === 'boolean') return;
  if (t === 'number') {
    if (!Number.isFinite(value as number)) {
      throw new ImpureContextError(
        `Non-finite number at ${path} — JSON.stringify would turn it into null, ` +
          'i.e. a hole in a device configuration.',
        path,
      );
    }
    return;
  }
  if (t === 'undefined' || t === 'function' || t === 'symbol' || t === 'bigint') {
    throw new ImpureContextError(`Value of type "${t}" at ${path} is not JSON.`, path);
  }

  if (seen.has(value)) {
    throw new ImpureContextError(`Circular reference at ${path}.`, path);
  }
  seen.add(value);

  if (Array.isArray(value)) {
    if (Object.getPrototypeOf(value) !== Array.prototype) {
      throw new ImpureContextError(`Array at ${path} has a tampered prototype.`, path);
    }
    value.forEach((v, i) => assertJsonPure(v, `${path}[${i}]`, seen, depth + 1));
    seen.delete(value);
    return;
  }

  const proto = Object.getPrototypeOf(value) as object | null;
  if (proto !== Object.prototype && proto !== null) {
    throw new ImpureContextError(
      `Object at ${path} is a live instance (prototype "${
        (proto as { constructor?: { name?: string } })?.constructor?.name ?? 'unknown'
      }"), not a plain JSON object. Nothing carrying a prototype crosses into ` +
        'the render worker.',
      path,
    );
  }
  for (const k of Object.getOwnPropertyNames(value)) {
    if (FORBIDDEN_KEYS.has(k)) {
      throw new ImpureContextError(`Forbidden key "${k}" at ${path} (prototype pollution).`, path);
    }
    const d = Object.getOwnPropertyDescriptor(value, k);
    if (d && (typeof d.get === 'function' || typeof d.set === 'function')) {
      throw new ImpureContextError(`Accessor property "${k}" at ${path} is not JSON.`, path);
    }
    assertJsonPure((value as Record<string, unknown>)[k], `${path}.${k}`, seen, depth + 1);
  }
  if (Object.getOwnPropertySymbols(value).length > 0) {
    throw new ImpureContextError(`Symbol-keyed property at ${path} is not JSON.`, path);
  }
  seen.delete(value);
}

/**
 * Re-materialise a value through JSON so that whatever object identity it had
 * on this side of the boundary is gone. `assertJsonPure` has already run, so
 * this cannot lose information; the reviver exists only so a `__proto__` key
 * smuggled in as raw jsonb text cannot be revived as a real prototype.
 */
export function jsonClone<T>(value: T): T {
  return JSON.parse(JSON.stringify(value), (k: string, v: unknown) =>
    FORBIDDEN_KEYS.has(k) ? undefined : v,
  ) as T;
}

// ============================================================================
// var_schema — JSON Schema plus the ObliWAN extension keywords
// ============================================================================

/**
 * `x-obliwan-secret` — the property's value comes from the vault. Declared in
 *   the schema so the TEMPLATE states which of its inputs are secret; the row's
 *   `is_secret` column states how the value is STORED. If the two disagree we
 *   fail closed (see `applySchema`).
 * `x-obliwan-level` — the level at which the author expects the variable to be
 *   defined. Used verbatim in the "required but unresolved" error, so that an
 *   operator is told WHERE to go and fix it. `'site'` is also the author's
 *   OPT-IN to the site form: `setSiteValues` accepts a key only when every
 *   published declaration of it says `'site'` (see `declaredSiteKeys`). A key
 *   the author left at `tenant`, `group` or `device`, or at no stated level, is
 *   not typed through that form, whatever its type would allow.
 *   `'computed'` and `'bench'` say the value is not stored at all: the caller
 *   of the render supplies it (`RenderTimeValues`), and only that caller.
 *   `'instance'` says a platform administrator stores it once for every tenant.
 */
export interface VarSchema {
  type?: 'object';
  properties?: Record<string, Record<string, unknown>>;
  required?: string[];
  additionalProperties?: boolean;
  [k: string]: unknown;
}

function newAjv(): Ajv {
  const instance = new Ajv({
    allErrors: true,
    // `verbose` stays OFF: it copies the offending DATA into every error
    // object, and error objects end up in logs. A secret must not reach a log
    // through a validation failure. The render-time instance (`ajv`
    // below) is never handed a secret at all (see `stripSecrets`), and for it
    // this is the second lock on that door. The site form's instance
    // (`siteAjv`) IS handed one — a declared secret's value is checked against
    // its declaration once, when it is typed — and for that path this option
    // is the first lock; the second is that `checkAgainstDeclarations` reports
    // only ajv's KEYWORD for a secret, never a message or a param.
    verbose: false,
    useDefaults: false, // defaults are applied by us, WITH their origin
    strict: false,
    coerceTypes: false, // the string "835" is not an integer VLAN id
  });
  addFormats(instance);
  instance.addKeyword({ keyword: 'x-obliwan-secret', schemaType: 'boolean' });
  instance.addKeyword({ keyword: 'x-obliwan-level', schemaType: 'string' });
  instance.addKeyword({ keyword: 'x-obliwan-label', schemaType: 'string' });
  // How the value is read off a router in service (infra analysis). An
  // annotation to every render: its grammar is judged by the template
  // validator (`varSchemaDiscoverProblems`), never by ajv.
  instance.addKeyword({ keyword: 'x-obliwan-discover', schemaType: 'object' });
  return instance;
}

/** The render-time compiler. It is never handed a secret's value. */
const ajv = newAjv();

/**
 * The site form's compiler: the same options, its own instance. The site form
 * validates declared SECRETS (`checkAgainstDeclarations`), and giving it a
 * separate instance keeps the render-time one's guarantee — never handed a
 * secret — true of that instance as a whole rather than of most of its
 * callers.
 */
const siteAjv = newAjv();

/** Compiling a schema costs about a millisecond; a rollout resolves it once per
 *  device. Cache on the schema's own hash so two revisions sharing a schema
 *  share the validator, and a schema edit invalidates itself. */
const validatorCache = new LRUCache<string, ValidateFunction>({ max: 200 });

function schemaKey(schema: VarSchema): string {
  return crypto.createHash('sha256').update(JSON.stringify(schema)).digest('hex');
}

/** Compile (and cache) a `var_schema`. Throws `VarSchemaError` on a bad one — a
 *  template revision must not be publishable with a schema nobody can run. */
export function compileVarSchema(schema: VarSchema): ValidateFunction {
  const k = schemaKey(schema);
  const hit = validatorCache.get(k);
  if (hit) return hit;
  let fn: ValidateFunction;
  try {
    fn = ajv.compile(schema as object);
  } catch (e) {
    throw new VarSchemaError(`var_schema is not a valid JSON Schema: ${(e as Error).message}`);
  }
  validatorCache.set(k, fn);
  return fn;
}

/** OWN properties only. `schema.properties` is parsed from jsonb and therefore
 *  carries `Object.prototype`; `properties['constructor']` on such an object
 *  returns the Object constructor, and every keyword lookup below would then be
 *  reading a function's fields. */
function propOf(schema: VarSchema, key: string): Record<string, unknown> | undefined {
  const props = schema.properties;
  if (!props || !Object.prototype.hasOwnProperty.call(props, key)) return undefined;
  return props[key];
}

function declaredSecret(schema: VarSchema, key: string): boolean {
  return propOf(schema, key)?.['x-obliwan-secret'] === true;
}

/** The level a declaration states, or null when it states none (or one that
 *  does not exist — the revision validator refuses that at authoring time). */
function declaredLevel(schema: VarSchema | null, key: string): VariableLevel | null {
  if (!schema) return null;
  const lvl = propOf(schema, key)?.['x-obliwan-level'];
  return typeof lvl === 'string' && (VARIABLE_LEVELS as readonly string[]).includes(lvl)
    ? (lvl as VariableLevel)
    : null;
}

function expectedLevel(schema: VarSchema, key: string): VariableLevel {
  return declaredLevel(schema, key) ?? 'device';
}

function isRenderTimeLevel(level: VariableLevel | null): level is RenderTimeLevel {
  return level !== null && (RENDER_TIME_LEVELS as readonly string[]).includes(level);
}

function isReservedFactKey(key: string): key is (typeof RESERVED_FACT_KEYS)[number] {
  return (RESERVED_FACT_KEYS as readonly string[]).includes(key);
}

// ============================================================================
// The chain query — ONE round-trip, all six stored levels
// ============================================================================

/** One row of the chain, as the query returns it. Exported for the harness,
 *  which folds hand-built rows to prove the precedence without a database. */
export interface ChainRow {
  scope: StoredVariableScope;
  rank: number;
  depth: number | null;
  src_id: number | null;
  src_name: string | null;
  key: string;
  /** NULL exactly when `is_secret` (migration 008, decision 6). */
  value: unknown;
  is_secret: boolean;
  /** The vault blob. NOT NULL exactly when `is_secret`. */
  secret_enc: string | null;
}

/**
 * What the chain is resolved FOR.
 *
 * `deviceId` set — the ordinary render path. The site level is then read from
 * THAT device's own `devices.site_id`, inside the query; `siteId` is ignored.
 *   A caller can therefore never make a router inherit another premises'
 *   values by passing the wrong site — the device says where it is.
 * `deviceId` null, `siteId` set — the bench path: the router has no row yet
 *   and the site is the only identity it has (`resolveForSite`).
 * both null — a group or tenant view; the site branch matches nothing.
 */
interface ChainTarget {
  groupId: number | null;
  deviceId: number | null;
  siteId: number | null;
}

/**
 * Load every override that applies to a target, ordered so that a plain
 * left-to-right fold produces the right precedence:
 *
 *   instance  <  global  <  tenant  <  group(root)  < ... <  group(leaf)  <  site  <  device
 *
 * `ORDER BY rank, depth DESC` IS the precedence rule, with the ranks taken
 * from `VARIABLE_SCOPE_RANK`; the rows are then re-sorted with
 * `compareChainOrder`, which is the same rule in TypeScript (a stable sort, so
 * it changes nothing when the two agree, and it is the one the harness proves).
 * `depth` is the closure distance from the device's own group, so the FARTHEST
 * ancestor comes first and the device's own group comes last — the same
 * ordering `settings.service._ancestorOverrides` uses, for the same reason.
 *
 * The tenant guards that must never be removed:
 *   - `dg.tenant_id = :tenantId` — a cross-tenant closure edge
 *     must not let another customer's group inject a variable here.
 *   - `s.tenant_id = :tenantId` on the site branch, and `d.tenant_id` in its
 *     sub-select — `devices.site_id` carries no tenant-aware constraint of its
 *     own, so a site id pointing into another tenant resolves to zero rows,
 *     not to that customer's VLAN plan.
 *   - `d.tenant_id = :tenantId` on the device branch — the same argument one
 *     level down: a device id belonging to another tenant resolves to zero
 *     rows, not to that tenant's overrides.
 */
async function chainRows(
  executor: Knex | Knex.Transaction,
  tenantId: number,
  target: ChainTarget,
): Promise<ChainRow[]> {
  const R = VARIABLE_SCOPE_RANK;
  // The ranks are integers from a frozen constant in this file, never input,
  // so interpolating them is not an injection surface; the ids all travel as
  // bindings. There is no `?` anywhere in this text: knex would rewrite it.
  //
  // The INSTANCE branch is the only one without a tenant predicate, and it is
  // the only one that may lack it: its rows are exactly those with a NULL
  // `tenant_id` (migration 038's CHECK ties `scope = 'instance'` to it), so
  // `tenant_id is null` is not a missing guard but the definition of the
  // level. It is not the first branch only because the first branch names the
  // columns of the whole UNION.
  const sql = `
    select 'global'::text as scope, ${R.global} as rank, null::int as depth,
           null::int as src_id, null::text as src_name,
           cv.key, cv.value, cv.is_secret, cv.secret_enc
      from config_variables cv
     where cv.tenant_id = :tenantId and cv.scope = 'global' and cv.scope_id is null
    union all
    select 'instance'::text, ${R.instance}, null::int, null::int, null::text,
           cv.key, cv.value, cv.is_secret, cv.secret_enc
      from config_variables cv
     where cv.tenant_id is null and cv.scope = 'instance' and cv.scope_id is null
    union all
    select 'tenant'::text, ${R.tenant}, null::int, t.id, t.name,
           cv.key, cv.value, cv.is_secret, cv.secret_enc
      from config_variables cv
      join tenants t on t.id = cv.tenant_id
     where cv.tenant_id = :tenantId and cv.scope = 'tenant' and cv.scope_id is null
    union all
    select 'group'::text, ${R.group}, gc.depth, dg.id, dg.name,
           cv.key, cv.value, cv.is_secret, cv.secret_enc
      from group_closure gc
      join device_groups dg on dg.id = gc.ancestor_id
      join config_variables cv
        on cv.scope_id = gc.ancestor_id and cv.scope = 'group' and cv.tenant_id = :tenantId
     where gc.descendant_id = :groupId
       and dg.tenant_id = :tenantId
    union all
    select 'site'::text, ${R.site}, null::int, s.id, s.name,
           cv.key, cv.value, cv.is_secret, cv.secret_enc
      from config_variables cv
      join sites s on s.id = cv.scope_id and s.tenant_id = :tenantId
     where cv.tenant_id = :tenantId and cv.scope = 'site'
       and cv.scope_id = (
             case when :deviceId > 0
                  then (select d.site_id from devices d
                         where d.id = :deviceId and d.tenant_id = :tenantId)
                  else :siteId
             end)
    union all
    select 'device'::text, ${R.device}, null::int, d.id, d.name,
           cv.key, cv.value, cv.is_secret, cv.secret_enc
      from config_variables cv
      join devices d on d.id = cv.scope_id and d.tenant_id = :tenantId
     where cv.tenant_id = :tenantId and cv.scope = 'device' and cv.scope_id = :deviceId
     order by 2 asc, 3 desc nulls last
  `;
  const res = (await executor.raw(sql, {
    tenantId,
    // A device with no group, a group-level preview with no device, a bench
    // target with no device: the corresponding branch matches nothing. Still
    // one query. -1 rather than NULL so `= :x` never needs an IS NULL twin.
    groupId: target.groupId ?? -1,
    deviceId: target.deviceId ?? -1,
    // Never bound on the device path, whatever the caller holds: the CASE
    // above already ignores it there, and not binding it makes "the device
    // says where it is" true of the inputs as well as of the SQL.
    siteId: target.deviceId === null ? (target.siteId ?? -1) : -1,
  })) as { rows?: ChainRow[] };
  return (res.rows ?? []).sort(compareChainOrder);
}

/** The chain that was actually searched, for the "where do I go and fix this"
 *  half of the error message. Only run when something is wrong. */
async function describeChain(
  executor: Knex | Knex.Transaction,
  tenantId: number,
  t: {
    groupId: number | null;
    siteId: number | null;
    siteName: string | null;
    deviceId: number | null;
    deviceName: string | null;
  },
): Promise<ChainStep[]> {
  const steps: ChainStep[] = [
    { scope: 'instance', scopeId: null, label: 'Instance (every tenant)', depth: null },
    { scope: 'global', scopeId: null, label: 'Global', depth: null },
    { scope: 'tenant', scopeId: tenantId, label: `Tenant #${tenantId}`, depth: null },
  ];
  if (t.groupId !== null) {
    const groups = (await executor('group_closure')
      .join('device_groups', 'device_groups.id', 'group_closure.ancestor_id')
      .where('group_closure.descendant_id', t.groupId)
      .where('device_groups.tenant_id', tenantId)
      .orderBy('group_closure.depth', 'desc')
      .select(
        'device_groups.id as id',
        'device_groups.name as name',
        'group_closure.depth as depth',
      )) as { id: number; name: string; depth: number }[];
    for (const g of groups) {
      steps.push({ scope: 'group', scopeId: g.id, label: `Group "${g.name}"`, depth: g.depth });
    }
  }
  if (t.siteId !== null) {
    steps.push({
      scope: 'site',
      scopeId: t.siteId,
      label: t.siteName ? `Site "${t.siteName}"` : `Site #${t.siteId}`,
      depth: null,
    });
  }
  if (t.deviceId !== null) {
    steps.push({
      scope: 'device',
      scopeId: t.deviceId,
      label: t.deviceName ? `Device "${t.deviceName}"` : `Device #${t.deviceId}`,
      depth: null,
    });
  }
  return steps;
}

// ============================================================================
// Fold: rows -> resolved variables
// ============================================================================

function sourceNameOf(row: ChainRow, tenantId: number): string {
  switch (row.scope) {
    case 'instance':
      return 'Instance';
    case 'global':
      return 'Global';
    case 'tenant':
      return row.src_name ?? `Tenant #${tenantId}`;
    case 'group':
      return row.src_name ?? `Group #${row.src_id}`;
    case 'site':
      return row.src_name ?? `Site #${row.src_id}`;
    case 'device':
      return row.src_name ?? `Device #${row.src_id}`;
  }
}

export interface FoldResult {
  variables: ResolvedVariables;
  /** key -> plaintext, IN MEMORY ONLY. Never returned to a caller that did not
   *  explicitly ask for secrets. */
  plaintexts: Map<string, string>;
  rejected: RejectedVariable[];
}

/**
 * Fold rows ALREADY in chain order (`compareChainOrder`) into resolved
 * variables: the last row for a key wins. Exported as `foldChain` for the
 * harness, which proves the precedence on hand-built rows; nothing in the
 * server calls it under that name.
 */
export function foldChain(tenantId: number, rows: ChainRow[]): FoldResult {
  return fold(tenantId, rows);
}

function fold(tenantId: number, rows: ChainRow[]): FoldResult {
  // NULL-PROTOTYPE, and this is not a micro-optimisation.
  //
  // `constructor`, `prototype`, `toString`, `valueOf` and `hasOwnProperty` all
  // match `VARIABLE_KEY_RE` and are all legal `config_variables.key` values as
  // far as migration 008's CHECK is concerned. On a `{}` map,
  // `variables['toString']` returns a FUNCTION inherited from
  // `Object.prototype`, so `if (variables[key] !== undefined)` reads "already
  // resolved" for a variable nobody ever set, `applySchema` skips its default,
  // and a caller reading `report.variables[key].value` gets a live function
  // instead of a value. The verification run caught exactly this.
  const variables: ResolvedVariables = Object.create(null) as ResolvedVariables;
  const plaintexts = new Map<string, string>();
  const rejected: RejectedVariable[] = [];

  for (const row of rows) {
    // A row whose key the API could not have written did not come through the
    // API. Skip it — and say so, loudly — rather than let it near a context.
    if (!VARIABLE_KEY_RE.test(row.key) || FORBIDDEN_KEYS.has(row.key)) {
      rejected.push({
        key: row.key,
        scope: row.scope,
        scopeId: row.src_id,
        reason: 'key does not match VARIABLE_KEY_RE — refused, never rendered',
      });
      continue;
    }
    if (isContextFactKey(row.key)) {
      // A row the API refuses to write (`storedVariableKey`, `assertWritable`):
      // one stored before that rule, or behind the API's back. Rendered, it
      // would collide with the facts the render supplies under that name —
      // with a plain Error on the device path, and for EVERY tenant when the
      // row is an instance one. Rejected here instead, by name, so the refusal
      // says which row to delete (the DELETE routes still accept the key).
      rejected.push({
        key: row.key,
        scope: row.scope,
        scopeId: row.src_id,
        reason:
          `"${row.key}" names a fact object the render supplies (${CONTEXT_FACT_KEYS.join(', ')}) ` +
          '— refused, never rendered; delete the row',
      });
      continue;
    }

    const base = {
      key: row.key,
      source: row.scope,
      sourceId: row.scope === 'global' || row.scope === 'instance' ? null : row.src_id,
      sourceName: sourceNameOf(row, tenantId),
      sourceDepth: row.depth,
    };

    if (row.is_secret) {
      if (typeof row.secret_enc !== 'string' || row.secret_enc.length === 0) {
        rejected.push({
          key: row.key,
          scope: row.scope,
          scopeId: row.src_id,
          reason: 'is_secret row carries no secret_enc blob',
        });
        // Fail CLOSED: drop the lower-precedence value too. A half-resolved
        // secret is worse than a missing one — the render must stop.
        delete variables[row.key];
        plaintexts.delete(row.key);
        continue;
      }
      let plain: string;
      try {
        plain = decrypt(row.secret_enc);
      } catch (e) {
        rejected.push({
          key: row.key,
          scope: row.scope,
          scopeId: row.src_id,
          // VaultError names the key_version and nothing else — safe to keep.
          reason: `vault: ${(e as Error).message}`,
        });
        delete variables[row.key];
        plaintexts.delete(row.key);
        continue;
      }
      plaintexts.set(row.key, plain);
      variables[row.key] = {
        ...base,
        value: redactedPlaceholder(row.key),
        isSecret: true,
        redacted: true,
        fingerprint: fingerprintSecret(tenantId, row.key, plain),
      };
      continue;
    }

    if (row.value === null || row.value === undefined) {
      // 008's CHECK makes this unreachable through SQL; reaching it means the
      // constraint was dropped. A NULL `value` on a clear row would render as
      // an empty string, which is the hole this service exists to prevent.
      rejected.push({
        key: row.key,
        scope: row.scope,
        scopeId: row.src_id,
        reason: 'non-secret row has a NULL value',
      });
      delete variables[row.key];
      continue;
    }

    if (typeof row.value === 'string' && VAULT_BLOB_RE.test(row.value)) {
      // A vault blob pasted into the CLEAR column. It would be pushed to the
      // router verbatim — a broken config AND a credential on the stored path.
      rejected.push({
        key: row.key,
        scope: row.scope,
        scopeId: row.src_id,
        reason: 'a vault blob is stored in the clear `value` column',
      });
      continue;
    }

    // A non-secret at a narrower scope legitimately overrides a secret set
    // wider: drop the stale plaintext with it.
    plaintexts.delete(row.key);
    variables[row.key] = {
      ...base,
      value: row.value as JsonValue,
      isSecret: false,
      redacted: false,
      fingerprint: null,
    };
  }

  return { variables, plaintexts, rejected };
}

// ============================================================================
// Schema pass: defaults, required, types
// ============================================================================

function applySchema(
  schema: VarSchema | null,
  variables: ResolvedVariables,
  plaintexts: Map<string, string>,
  /** Render-time secrets laid as placeholders with no plaintext on purpose
   *  (`RenderTimeValues.withheld`): resolved for a redacted render. */
  withheld: ReadonlySet<string> = new Set(),
): { missing: MissingVariable[]; typeErrors: VariableTypeError[] } {
  const missing: MissingVariable[] = [];
  const typeErrors: VariableTypeError[] = [];
  if (!schema) return { missing, typeErrors };

  const props = schema.properties ?? {};
  const required = new Set(schema.required ?? []);

  // 1. Defaults — applied by us, not by ajv's `useDefaults`, because a default
  //    that arrives through mutation loses the one thing the UI needs: where
  //    the value came from.
  for (const [key, prop] of Object.entries(props)) {
    if (!VARIABLE_KEY_RE.test(key) || FORBIDDEN_KEYS.has(key)) {
      typeErrors.push({
        key,
        message: `is declared by var_schema but is not a legal variable name (${VARIABLE_KEY_RE})`,
        source: 'default',
        sourceName: 'var_schema',
      });
      continue;
    }
    if (variables[key] !== undefined) continue;
    if (!('default' in prop)) continue;
    if (declaredLevel(schema, key) === 'computed' || isReservedFactKey(key)) {
      // The revision validator refuses both; meeting one here means a schema
      // written behind it. A default would render a value ObliWAN never
      // computed — an identity, an address — the moment the caller forgot it.
      typeErrors.push({
        key,
        message:
          'is declared computed (or names the site/box facts) and given a default — its value ' +
          'is supplied at render time, never by the revision',
        source: 'default',
        sourceName: 'var_schema',
      });
      continue;
    }
    if (declaredSecret(schema, key)) {
      // A default for a SECRET would be a plaintext credential sitting in the
      // revision body, which is exactly what the vault exists to avoid.
      typeErrors.push({
        key,
        message: 'is declared secret and given a default — a secret has no default',
        source: 'default',
        sourceName: 'var_schema',
      });
      continue;
    }
    variables[key] = {
      key,
      value: prop.default as JsonValue,
      source: 'default',
      sourceId: null,
      sourceName: 'Default',
      sourceDepth: null,
      isSecret: false,
      redacted: false,
      fingerprint: null,
    };
  }

  // 2. Secret / non-secret agreement, both directions. Fail closed.
  for (const key of Object.getOwnPropertyNames(props)) {
    const v = variables[key];
    if (!v) continue;
    if (declaredSecret(schema, key) && !v.isSecret) {
      typeErrors.push({
        key,
        message: `is declared secret by the template but is stored in clear at ${v.sourceName}`,
        source: v.source,
        sourceName: v.sourceName,
      });
    }
    if (!declaredSecret(schema, key) && v.isSecret) {
      typeErrors.push({
        key,
        message:
          'is stored as a secret but the template does not declare "x-obliwan-secret": ' +
          'the rendered value would be a placeholder',
        source: v.source,
        sourceName: v.sourceName,
      });
    }
  }

  // 3. Required and unresolved -> a NAMED error, never a hole.
  for (const key of required) {
    const v = variables[key];
    const resolved = v !== undefined && (!v.isSecret || plaintexts.has(key) || withheld.has(key));
    if (!resolved) {
      missing.push({
        key,
        expectedScope: expectedLevel(schema, key),
        reason: declaredSecret(schema, key)
          ? 'secret-declared-but-absent'
          : 'required-and-unresolved',
      });
    }
  }

  // 4. Types. Secrets are EXCLUDED from this validation on purpose: ajv builds
  //    error strings, error strings reach logs, and a secret must not.
  //    What can still be checked about a secret without looking at it — that
  //    it exists, and that it decrypted — has been checked above. A secret's
  //    TYPE is checked once, when it is typed into the site form, by the
  //    separate `siteAjv` instance, which reports only the keyword; a secret
  //    written through the generic TEMPLATE_WRITE routes is held to nothing
  //    but those two facts and to being a string. A secret supplied at render
  //    time (`computed`, `bench`) is checked keyword-only against its
  //    declaration as it arrives, in `applyRenderTimeValues`.
  //
  //    ONLY THE DECLARED KEYS are judged. The chain carries the values of every
  //    template the tenant uses — and, since migration 038, the instance-wide
  //    values of every tenant's templates — so a root keyword that judges the
  //    KEY SET (`additionalProperties: false`, `propertyNames`,
  //    `maxProperties`) would make one revision's renderability depend on
  //    variables somebody set for another template, possibly in another
  //    tenant's name. A var_schema types the revision's inputs; the rest of
  //    the chain is somebody else's business.
  const validate = compileVarSchema(stripSecrets(schema));
  const subject: Record<string, unknown> = Object.create(null) as Record<string, unknown>;
  for (const [key, v] of Object.entries(variables)) {
    if (v.isSecret || declaredSecret(schema, key)) continue;
    if (!propOf(schema, key)) continue;
    subject[key] = v.value;
  }
  if (!validate(subject)) {
    for (const err of validate.errors ?? []) {
      // `required` is reported by us, with a level to go and fix it. Do not
      // duplicate it as an opaque type error.
      if (err.keyword === 'required') continue;
      const key = err.instancePath.startsWith('/')
        ? err.instancePath.slice(1).split('/')[0]
        : ((err.params as { additionalProperty?: string })?.additionalProperty ?? '(document)');
      const v = variables[key];
      const sub = err.instancePath.slice(Math.min(key.length + 1, err.instancePath.length));
      typeErrors.push({
        key,
        message: `${sub ? sub + ' ' : ''}${err.message ?? 'is invalid'}`,
        source: v?.source ?? 'default',
        sourceName: v?.sourceName ?? 'var_schema',
      });
    }
  }

  return { missing, typeErrors };
}

/** A copy of the schema with the secret properties removed, so the render-time
 *  validation never sees a secret value AND never reports `required` on one
 *  (that path is ours). */
function stripSecrets(schema: VarSchema): VarSchema {
  const props = schema.properties ?? {};
  const secretKeys = Object.keys(props).filter((k) => props[k]?.['x-obliwan-secret'] === true);
  const out: VarSchema = { ...schema };
  if (secretKeys.length > 0) {
    const p: Record<string, Record<string, unknown>> = {};
    for (const [k, v] of Object.entries(props)) if (!secretKeys.includes(k)) p[k] = v;
    out.properties = p;
  }
  // `required` is enforced by us, with a device name and a level. ajv's version
  // of the same message has neither.
  delete out.required;
  return out;
}

// ============================================================================
// Render-time values — `computed`, `bench`, and the site / box facts
// ============================================================================

/**
 * What the CALLER of a render supplies, in memory, for one render.
 *
 *  - `computed` — ObliWAN's own values (the allocator's outputs). A SUPERSET is
 *    welcome: only the keys the revision declares `computed` are taken, the
 *    rest are listed in `VariableReport.unusedComputed` and not rendered.
 *  - `bench`    — typed at the bench for ONE box. EVERY key must be declared
 *    `bench` by the revision: a value somebody typed and the render then
 *    dropped would ship a box with the default instead (the tenant's SIM PIN
 *    rather than the one on the card), so an undeclared key is refused.
 *  - `facts`    — `site` and `box` (`RESERVED_FACT_KEYS`), from the site record
 *    and the box on the bench. Undeclared, they reach the context as nested
 *    objects (like the device path's `device`); declared at a render-time
 *    level, the declaration TYPES them.
 *
 * A secret in `computed` or `bench` is a plaintext and stays one: it is never
 * written anywhere, reaches the context only in `'secrets'` mode, and is
 * checked against its declaration with ajv's KEYWORD only, never a message.
 *
 *  - `withheld` — render-time SECRETS the caller does not hold, by key: the
 *    device path (`render.service`), rendering a bench-prepared router after
 *    the fact, where the SIM PIN was typed for the box once and kept nowhere
 *    and the PPP password is not read for a redacted render. Each must be
 *    declared secret at the `computed` or `bench` level. It resolves to its
 *    placeholder with NO fingerprint (nothing is known of the value), counts
 *    as resolved in a report — a redacted render needs only the placeholder —
 *    and refuses a `'secrets'` context, which would need the value
 *    (`contextFromReport`: "could not be read from the values supplied").
 *    Nothing is invented for it: no stand-in value, no fake fingerprint.
 */
export interface RenderTimeValues {
  computed?: Record<string, unknown>;
  bench?: Record<string, unknown>;
  facts?: Record<string, unknown>;
  withheld?: readonly string[];
}

export interface RenderTimeOverlay {
  shadowed: ShadowedVariable[];
  unusedComputed: string[];
  /** Refusals. Every message names the KEY, never the value. */
  errors: VariableTypeError[];
  /** Facts the revision does not declare, for the context's `extra`. */
  undeclaredFacts: Record<string, JsonValue>;
  /** The `withheld` keys laid as placeholders (see `RenderTimeValues`). */
  withheld: string[];
}

const RENDER_TIME_SOURCE_NAMES: Readonly<Record<RenderTimeLevel, string>> = Object.freeze({
  computed: 'Computed by ObliWAN',
  bench: 'Typed at the bench',
});

const FACT_SOURCE_NAMES: Readonly<Record<(typeof RESERVED_FACT_KEYS)[number], string>> =
  Object.freeze({ site: 'Site record', box: 'Box on the bench' });

function ownEntries(map: Record<string, unknown> | undefined): [string, unknown][] {
  if (!map || typeof map !== 'object' || Array.isArray(map)) return [];
  return Object.getOwnPropertyNames(map).map((k) => [k, (map as Record<string, unknown>)[k]]);
}

/**
 * A render-time SECRET against its declaration, on the site form's ajv
 * instance (the one allowed to see a secret), reporting the keyword only — the
 * same discipline as `checkAgainstDeclarations`. Null when it satisfies it.
 */
function secretDeclarationProblem(schema: VarSchema, key: string, value: string): string | null {
  let validate: ValidateFunction;
  try {
    validate = compileSiteSchema(siteFormSchema(schema));
  } catch {
    return 'cannot be checked: its declaration does not compile without the schema\'s ' +
      'cross-variable keywords';
  }
  const instance = Object.create(null) as Record<string, unknown>;
  instance[key] = value;
  if (validate(instance)) return null;
  const keywords = [...new Set((validate.errors ?? []).map((e) => e.keyword))];
  return `does not satisfy its declaration (${keywords.join(', ') || 'invalid'})`;
}

/**
 * Lay the caller's render-time values over a folded chain. Pure apart from the
 * fingerprint key — exported for the harness. Mutates `variables` and
 * `plaintexts` (the fold's own maps), and is run BEFORE `applySchema`, so a
 * supplied value is type-checked and counts as resolved, and a required
 * render-time key that was not supplied is reported missing at its own level.
 *
 * In order:
 *  1. every stored row for a key the revision declares `computed` or `bench`
 *     is set aside (`shadowed`): the declaration says who supplies the value,
 *     and a stale site value must not stand in for the allocator's answer;
 *  2. facts — undeclared ones are handed back for `extra`, declared ones are
 *     laid over like a render-time value of their declared level;
 *  3. `computed` — declared keys taken, the others listed as unused;
 *  4. `bench`    — declared keys taken, any other key refused;
 *  5. `withheld` — declared render-time SECRETS laid as their placeholder,
 *     with no fingerprint; any other key, or one also supplied, refused.
 */
export function applyRenderTimeValues(
  tenantId: number,
  schema: VarSchema | null,
  variables: ResolvedVariables,
  plaintexts: Map<string, string>,
  supplied: RenderTimeValues,
): RenderTimeOverlay {
  const shadowed: ShadowedVariable[] = [];
  const unusedComputed: string[] = [];
  const errors: VariableTypeError[] = [];
  const undeclaredFacts: Record<string, JsonValue> = {};

  // 1. Shadow.
  if (schema && schema.properties && typeof schema.properties === 'object') {
    for (const key of Object.getOwnPropertyNames(schema.properties)) {
      const level = declaredLevel(schema, key);
      const v = variables[key];
      if (!isRenderTimeLevel(level) || v === undefined) continue;
      shadowed.push({ key, declaredLevel: level, storedAt: v.source, storedAtName: v.sourceName });
      delete variables[key];
      plaintexts.delete(key);
    }
  }

  const refuse = (key: string, level: RenderTimeLevel | 'facts', message: string): void => {
    errors.push({
      key,
      message,
      source: level === 'facts' ? 'computed' : level,
      sourceName: level === 'facts' ? 'render-time facts' : RENDER_TIME_SOURCE_NAMES[level],
    });
  };

  const legalName = (key: string, level: RenderTimeLevel): boolean => {
    if (!VARIABLE_KEY_RE.test(key) || FORBIDDEN_KEYS.has(key)) {
      refuse(key, level, `is not a legal variable name (${VARIABLE_KEY_RE})`);
      return false;
    }
    if (isReservedFactKey(key)) {
      refuse(
        key,
        level,
        `is reserved for the ${key} facts, which the render takes from their own parameter, ` +
          `never from the ${level} map`,
      );
      return false;
    }
    return true;
  };

  const lay = (
    key: string,
    value: unknown,
    level: RenderTimeLevel,
    sourceName: string,
  ): void => {
    const s = schema as VarSchema; // only reached for a key the schema declares
    if (declaredSecret(s, key)) {
      if (typeof value !== 'string' || value.length === 0 || value.length > SECRET_MAX_LENGTH) {
        refuse(
          key,
          level,
          `is declared secret: its value must be a non-empty string of at most ` +
            `${SECRET_MAX_LENGTH} characters`,
        );
        return;
      }
      const problem = secretDeclarationProblem(s, key, value);
      if (problem) {
        refuse(key, level, problem);
        return;
      }
      plaintexts.set(key, value);
      variables[key] = {
        key,
        value: redactedPlaceholder(key),
        source: level,
        sourceId: null,
        sourceName,
        sourceDepth: null,
        isSecret: true,
        redacted: true,
        fingerprint: fingerprintSecret(tenantId, key, value),
      };
      return;
    }
    try {
      assertJsonPure(value, `$.${key}`);
    } catch (e) {
      // ImpureContextError names the path and the type, never the value.
      refuse(key, level, (e as Error).message);
      return;
    }
    variables[key] = {
      key,
      value: jsonClone(value as JsonValue),
      source: level,
      sourceId: null,
      sourceName,
      sourceDepth: null,
      isSecret: false,
      redacted: false,
      fingerprint: null,
    };
  };

  // 2. Facts.
  for (const [key, value] of ownEntries(supplied.facts)) {
    if (!isReservedFactKey(key)) {
      refuse(key, 'facts', `is not a render-time fact (expected one of ${RESERVED_FACT_KEYS.join(', ')})`);
      continue;
    }
    const level = declaredLevel(schema, key);
    if (level === null && !propOf(schema ?? {}, key)) {
      try {
        assertJsonPure(value, `$.${key}`);
        undeclaredFacts[key] = jsonClone(value as JsonValue);
      } catch (e) {
        refuse(key, 'facts', (e as Error).message);
      }
      continue;
    }
    if (!isRenderTimeLevel(level) || declaredSecret(schema as VarSchema, key)) {
      refuse(
        key,
        'facts',
        `is declared by the revision at the ${level ?? 'unstated'} level${
          declaredSecret(schema as VarSchema, key) ? ', secret,' : ''
        } but names the ${key} facts the render supplies: declare it computed or bench, not secret`,
      );
      continue;
    }
    lay(key, value, level, FACT_SOURCE_NAMES[key]);
  }

  // 3. Computed — a superset is welcome.
  for (const [key, value] of ownEntries(supplied.computed)) {
    if (!legalName(key, 'computed')) continue;
    if (declaredLevel(schema, key) !== 'computed') {
      unusedComputed.push(key);
      continue;
    }
    lay(key, value, 'computed', RENDER_TIME_SOURCE_NAMES.computed);
  }

  // 4. Bench — every key must be declared there.
  for (const [key, value] of ownEntries(supplied.bench)) {
    if (!legalName(key, 'bench')) continue;
    const level = declaredLevel(schema, key);
    if (level !== 'bench') {
      refuse(
        key,
        'bench',
        `was typed at the bench, but the revision declares it ${
          level ? `at the ${level} level` : propOf(schema ?? {}, key) ? 'at no stated level' : 'nowhere'
        } — refused rather than silently dropped, which would ship the box with whatever the ` +
          'chain holds instead',
      );
      continue;
    }
    lay(key, value, 'bench', RENDER_TIME_SOURCE_NAMES.bench);
  }

  // 5. Withheld — a declared render-time secret the caller does not hold.
  const withheld: string[] = [];
  for (const key of supplied.withheld ?? []) {
    if (typeof key !== 'string') continue;
    const level = declaredLevel(schema, key);
    if (!legalName(key, isRenderTimeLevel(level) ? level : 'computed')) continue;
    if (!isRenderTimeLevel(level) || !declaredSecret(schema as VarSchema, key)) {
      refuse(
        key,
        isRenderTimeLevel(level) ? level : 'computed',
        'is withheld, but the revision does not declare it a computed or bench SECRET: only a ' +
          'secret renders as a placeholder whatever its value, so only a secret may be left unread',
      );
      continue;
    }
    if (variables[key] !== undefined) {
      refuse(key, level, 'is both supplied and withheld — the caller must say which');
      continue;
    }
    variables[key] = {
      key,
      value: redactedPlaceholder(key),
      source: level,
      sourceId: null,
      sourceName: `${RENDER_TIME_SOURCE_NAMES[level]} (not held by this render)`,
      sourceDepth: null,
      isSecret: true,
      redacted: true,
      fingerprint: null,
    };
    withheld.push(key);
  }

  unusedComputed.sort();
  return { shadowed, unusedComputed, errors, undeclaredFacts, withheld: withheld.sort() };
}

// ============================================================================
// Site values — typed data entry, not template authoring (SITE_VARIABLES_WRITE)
// ============================================================================
//
// The template-execution boundary, applied to a form. Whoever holds TEMPLATE_WRITE can make this server
// evaluate template code; whoever holds only SITE_VARIABLES_WRITE must not be
// able to come close. So the site writer accepts exactly four things:
//
//   1. a key some PUBLISHED revision of an ACTIVE template visible to the
//      tenant already declares — an account manager cannot invent a variable,
//      she fills one in;
//   2. a key EVERY such declaration opens to the site form with
//      `x-obliwan-level: 'site'`. SITE_VARIABLES_WRITE is role-derived — every
//      plain tenant member holds it — and a site value outranks every group
//      and the tenant, so "declared" alone would let any member override, for
//      one site, what an author published as fleet policy (a management CIDR,
//      a tenant-wide admin password), on the bench path too, where a render
//      goes straight onto a CPE. Which keys are per-site DATA is the author's
//      call, made per key, secrets included. A key nobody opened is written at
//      the site level only through the TEMPLATE_WRITE route
//      `PUT /api/variables/at/site/:siteId`;
//   3. a value that validates against EVERY published declaration of that key
//      (ajv, with the render-time options, on the site form's own instance) —
//      what she types is something each template consuming it can render. An
//      older published revision is not "superseded" for this purpose: pinned
//      assignments and the OS-version walk-down of `assignment.service` still
//      render it;
//   4. secrecy decided by the declaration's `x-obliwan-secret`, never by her —
//      a declared secret goes to the vault, and nothing in her request can
//      route it to the clear `value` column.
//
// A value is still an input to a render, and a VLAN id is still something a
// router is configured with; what this boundary guarantees is that the value
// is DATA of the type the template's author published, for a key that author
// published as per-site data, nothing more.

/** One published revision's declarations, as the site writer sees them. */
export interface SiteVariableDeclaration {
  templateId: number;
  templateName: string;
  revisionId: number;
  revision: number;
  /** A shipped library revision (`tenant_id` NULL). Read-only to every tenant
   *  — `templates.controller` answers 403 to a status change on one — so a
   *  refusal must never tell the operator to deprecate it. */
  library: boolean;
  varSchema: VarSchema;
}

/** Which revision declared a key — named in every refusal so the operator
 *  knows which template to take the question to. */
export interface DeclaredBy {
  templateId: number;
  templateName: string;
  revisionId: number;
  revision: number;
  library: boolean;
}

/** A declaration that keeps its key OUT of the site form, with the level it
 *  states instead — null when it states none. */
export interface WithheldBy extends DeclaredBy {
  level: VariableLevel | null;
}

/** One field of the site form. */
export interface DeclaredSiteKey {
  key: string;
  /** `x-obliwan-label` of the newest declaration, else null. */
  label: string | null;
  /** true when ANY declaration marks it `x-obliwan-secret` — a form masks it. */
  secret: boolean;
  /** `x-obliwan-level` of the newest declaration, else null. Informative only:
   *  whether the site form may write the key is `siteWritable`, which asks
   *  EVERY declaration, not just the newest. */
  level: VariableLevel | null;
  /** The property's JSON Schema in the newest published revision declaring it
   *  — what a form is generated from. */
  schema: Record<string, unknown>;
  declaredBy: DeclaredBy[];
  /** false when two published declarations of the key differ. A write must
   *  then satisfy every one of them. */
  consistent: boolean;
  /** Declarations disagree on `x-obliwan-secret`. Any storage choice would
   *  break one of the templates, so the key is unwritable here until a
   *  template author settles it. */
  secrecyConflict: boolean;
  /** true when EVERY published declaration of the key says
   *  `x-obliwan-level: 'site'` — the author's opt-in to typed entry through
   *  the site form. A form shows the other keys read-only, if at all. */
  siteWritable: boolean;
  /** The declarations that keep the key out of the form, newest first. Empty
   *  exactly when `siteWritable`. */
  withheldBy: WithheldBy[];
}

/** One refused entry. Names the KEY, never the value. */
export interface SiteValueError {
  key: string;
  message: string;
}

export interface SiteValuesVerdict {
  /** Present only when `errors` is empty — the request is all-or-nothing. */
  writes: { key: string; value: JsonValue; isSecret: boolean }[];
  unset: string[];
  errors: SiteValueError[];
}

/** What `GET /variables/sites/:siteId` returns. */
export interface SiteVariableForm {
  site: { id: number; code: string; name: string };
  /** Every value set AT the site level, redacted — declared or not (a template
   *  author may have set an undeclared one through the generic route). */
  values: ResolvedVariables;
  /** One entry per declared key, sorted by key. */
  declared: DeclaredSiteKey[];
}

/** `setVariableSchema`'s bound on a secret, repeated here because the site
 *  writer judges secrecy from the declaration, after the validator ran. */
const SECRET_MAX_LENGTH = 4096;

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

/** Key-order-independent JSON, so two declarations that differ only in the
 *  order jsonb handed their keys back are recognised as the same. */
function canonicalJson(v: unknown): string {
  if (Array.isArray(v)) return `[${v.map(canonicalJson).join(',')}]`;
  if (isPlainObject(v)) {
    return `{${Object.keys(v)
      .sort()
      .map((k) => `${JSON.stringify(k)}:${canonicalJson(v[k])}`)
      .join(',')}}`;
  }
  return JSON.stringify(v) ?? 'null';
}

/**
 * The form: every key declared by at least one published revision, merged
 * across revisions. `decls` is expected NEWEST FIRST (the loader orders it so),
 * which is what makes `schema`, `label` and `level` the newest declaration's.
 * `siteWritable` is the one verdict that asks every declaration: a single
 * revision still keeping the key at another level keeps it out of the form,
 * because a site value would override that revision's policy as well.
 *
 * Illegal names and non-object property schemas are skipped, not repaired: the
 * revision validator refuses both at authoring time, so meeting one here means
 * a row written behind the API's back, and it must not become a form field.
 */
export function declaredSiteKeys(
  decls: readonly SiteVariableDeclaration[],
): Map<string, DeclaredSiteKey> {
  const out = new Map<string, DeclaredSiteKey>();
  const shapes = new Map<string, string>();
  const secrecy = new Map<string, Set<boolean>>();

  for (const d of decls) {
    if (!isPlainObject(d.varSchema) || !isPlainObject(d.varSchema.properties)) continue;
    for (const key of Object.getOwnPropertyNames(d.varSchema.properties)) {
      if (!VARIABLE_KEY_RE.test(key) || FORBIDDEN_KEYS.has(key)) continue;
      const prop = propOf(d.varSchema, key);
      if (!isPlainObject(prop)) continue;

      const by: DeclaredBy = {
        templateId: d.templateId,
        templateName: d.templateName,
        revisionId: d.revisionId,
        revision: d.revision,
        library: d.library,
      };
      const isSecret = prop['x-obliwan-secret'] === true;
      const rawLevel = prop['x-obliwan-level'];
      const level =
        typeof rawLevel === 'string' && (VARIABLE_LEVELS as readonly string[]).includes(rawLevel)
          ? (rawLevel as VariableLevel)
          : null;
      const shape = canonicalJson(prop);
      const votes = secrecy.get(key) ?? new Set<boolean>();
      votes.add(isSecret);
      secrecy.set(key, votes);

      const known = out.get(key);
      if (known) {
        known.declaredBy.push(by);
        if (level !== 'site') known.withheldBy.push({ ...by, level });
        if (shape !== shapes.get(key)) known.consistent = false;
        continue;
      }
      const label = prop['x-obliwan-label'];
      out.set(key, {
        key,
        label: typeof label === 'string' ? label : null,
        secret: isSecret,
        level,
        schema: prop,
        declaredBy: [by],
        consistent: true,
        secrecyConflict: false,
        siteWritable: false, // settled below, once every declaration has voted
        withheldBy: level === 'site' ? [] : [{ ...by, level }],
      });
      shapes.set(key, shape);
    }
  }

  for (const [key, entry] of out) {
    entry.siteWritable = entry.withheldBy.length === 0;
    const votes = secrecy.get(key);
    if (votes && votes.size > 1) {
      entry.secrecyConflict = true;
      // Fail toward masking: a form must never echo what any template calls a
      // secret, even though the key is not writable until the conflict ends.
      entry.secret = true;
    }
  }
  return out;
}

/** The route that writes a site value WITHOUT the site form's rules — the one
 *  way out the refusals below can honestly name for a key the form will not
 *  take. TEMPLATE_WRITE, like every other write at every other level. */
const GENERIC_SITE_ROUTE = 'PUT /api/variables/at/site/:siteId';

/**
 * Root keywords that judge the WHOLE resolved set rather than one variable:
 * which keys must be present, which depend on which, conditions across keys,
 * bounds on the number of keys, a constraint on the document as one value.
 * The site form judges one key at a time against an instance holding only that
 * key, so each of these would refuse a correct value for want of its siblings
 * (`required`) or wave a value through for the same reason (`if`/`then`). They
 * are judged at render time, by `applySchema`, with the whole chain in hand.
 * `$id` is set aside too: ajv registers a schema under its `$id` and refuses a
 * second, different schema with the same one.
 */
const WHOLE_SET_KEYWORDS: ReadonlySet<string> = new Set([
  '$id', '$ref', '$dynamicRef', '$recursiveRef',
  'required', 'dependentRequired', 'dependentSchemas', 'dependencies',
  'if', 'then', 'else', 'allOf', 'anyOf', 'oneOf', 'not',
  'minProperties', 'maxProperties', 'const', 'enum',
]);

/**
 * A revision's `var_schema` as the site form evaluates it: the WHOLE document
 * minus `WHOLE_SET_KEYWORDS`, run against `{ [key]: value }`.
 *
 * The whole document rather than the one property, because a declaration may
 * `$ref` anything in it — `{ $ref: '#/properties/primary_dns' }` is valid JSON
 * Schema, compiles, publishes and renders — and a cut-down copy holding only
 * the property would leave that reference dangling and refuse every value with
 * a false "does not compile". The other properties cost nothing: the instance
 * carries only the key being judged, and `properties` constrains only the keys
 * present.
 *
 * One derived schema per REVISION, whatever the key, so the number of schemas
 * the site instance ever compiles is bounded by the number of distinct
 * published `var_schema`s, not by the key combinations people submit.
 */
function siteFormSchema(schema: VarSchema): VarSchema {
  const out: VarSchema = {};
  for (const k of Object.keys(schema)) {
    // A jsonb `__proto__` key is an OWN property after JSON.parse; assigning
    // it here would set `out`'s prototype instead of copying a keyword.
    if (WHOLE_SET_KEYWORDS.has(k) || FORBIDDEN_KEYS.has(k)) continue;
    out[k] = schema[k];
  }
  return out;
}

/** Same LRU discipline as `validatorCache`, on the site form's instance. */
const siteValidatorCache = new LRUCache<string, ValidateFunction>({ max: 200 });

function compileSiteSchema(schema: VarSchema): ValidateFunction {
  const k = schemaKey(schema);
  const hit = siteValidatorCache.get(k);
  if (hit) return hit;
  const fn = siteAjv.compile(schema as object);
  siteValidatorCache.set(k, fn);
  return fn;
}

/**
 * Does the revision's `var_schema`, exactly as published, compile? Asked only
 * after the site form's cut of it failed to, to tell "this revision is broken"
 * from "the site form cannot evaluate this declaration" — two different people
 * to send the operator to. A throwaway instance with the render-time options,
 * so the probe neither reads nor fills any shared schema registry (a `$id`
 * already registered would otherwise fail it for the wrong reason).
 */
function wholeSchemaCompiles(schema: VarSchema): boolean {
  try {
    newAjv().compile(schema as object);
    return true;
  } catch {
    return false;
  }
}

function nameOf(d: DeclaredBy): string {
  return `template "${d.templateName}" revision ${d.revision}`;
}

/**
 * What an operator can actually do when the declaration in `d` stands in the
 * way. Worded per case because the operations differ: a tenant's own revision
 * can be deprecated by a template author, a library revision cannot be by
 * anyone (`writableRevision` answers 403 to every tenant, platform admins
 * included), and telling an operator to do the impossible sends her nowhere.
 */
function wayOut(d: DeclaredBy): string {
  return d.library
    ? `${nameOf(d)} belongs to the shipped library, which no tenant can deprecate; a ` +
        'template author (TEMPLATE_WRITE) can set the value for this site through ' +
        `${GENERIC_SITE_ROUTE}, and the render then judges it against the revision that ` +
        'actually renders'
    : `a template author (TEMPLATE_WRITE) can deprecate ${nameOf(d)} through ` +
        `POST /api/templates/revisions/${d.revisionId}/status once no assignment renders ` +
        `it, or set the value for this site through ${GENERIC_SITE_ROUTE}, where the ` +
        'render judges it against the revision that actually renders';
}

/** ajv's verdict on one value, against every published declaration of it.
 *  At most ONE error per refusing declaration, its reasons joined. */
function checkAgainstDeclarations(
  decls: readonly SiteVariableDeclaration[],
  entry: DeclaredSiteKey,
  key: string,
  value: unknown,
): SiteValueError[] {
  const errors: SiteValueError[] = [];
  const several = entry.declaredBy.length > 1;
  for (const d of decls) {
    if (!propOf(d.varSchema, key)) continue;
    const by = nameOf(d);
    let validate: ValidateFunction;
    try {
      validate = compileSiteSchema(siteFormSchema(d.varSchema));
    } catch {
      errors.push({
        key,
        message: wholeSchemaCompiles(d.varSchema)
          ? `cannot be checked by the site form: the form evaluates the var_schema of ${by} ` +
            'without its cross-variable keywords and its $id, and this declaration does ' +
            'not compile without them (a $ref into one of them) — a template author ' +
            `(TEMPLATE_WRITE) can set it for this site through ${GENERIC_SITE_ROUTE}, where ` +
            'the render judges it against the whole schema'
          : `cannot be checked: ${by} carries a var_schema that does not compile — ` +
            wayOut(d),
      });
      continue;
    }
    // NULL-PROTOTYPE, as `applySchema`'s subject is. The schema is the whole
    // document, so it may declare `constructor` or `toString` — names the
    // regex accepts — and ajv's `properties` code reads `data.constructor`,
    // which on a `{}` is `Object` through the prototype: an inherited function
    // judged as a value nobody typed, refusing every key of that revision. The
    // harness caught exactly this.
    const instance = Object.create(null) as Record<string, unknown>;
    instance[key] = value;
    if (validate(instance)) continue;
    const own = `/${key}`;
    const reasons: string[] = [];
    for (const err of validate.errors ?? []) {
      const sub = err.instancePath.startsWith(own)
        ? err.instancePath.slice(own.length)
        : err.instancePath;
      // A secret's error carries only ajv's KEYWORD. `verbose` is off, so ajv's
      // own messages are built from the schema rather than the data — but
      // "never put anything derived from a secret in an error" is cheaper to
      // keep as a rule than to re-audit per keyword.
      const what = entry.secret
        ? `does not satisfy its declaration (${err.keyword})`
        : `${sub ? sub + ' ' : ''}${err.message ?? 'is invalid'}`;
      if (!reasons.includes(what)) reasons.push(what);
    }
    if (reasons.length === 0) reasons.push('is invalid');
    errors.push({
      key,
      message:
        `${reasons.join(', ')} — declared by ${by}` +
        (several
          ? '; a site value must satisfy every published revision that declares the key, ' +
            'older ones included, since pinned assignments and the OS-version walk-down ' +
            `still render them: ${wayOut(d)}`
          : ''),
    });
  }
  return errors;
}

/**
 * ajv's verdict on ONE value against ONE revision's `var_schema`, the way the
 * site form judges it (`checkAgainstDeclarations`: the schema minus its
 * whole-set keywords, a null-prototype instance holding only this key), but
 * at any level and without the site form's wording — for the Quick Setup
 * check, which types a tenant or instance value against the template it is
 * typed for before anything is stored.
 *
 * `{ reasons: [], uncheckable: false }` for a key the schema does not declare
 * (nothing to judge) and for a value it accepts; `uncheckable: true` when
 * the schema's site-form cut does not compile. A key declared
 * `x-obliwan-secret`, or a value the caller says is a secret (`opts.secret`),
 * gets ajv's KEYWORD only — never a message or a param — exactly as the site
 * form reports one. Uses `siteAjv`, the instance that is allowed to be handed
 * a secret (see `newAjv`).
 */
export function judgeValueAgainstSchema(
  schema: VarSchema,
  key: string,
  value: unknown,
  opts: { secret?: boolean } = {},
): { reasons: string[]; uncheckable: boolean } {
  if (!isPlainObject(schema) || !isPlainObject(propOf(schema, key))) {
    return { reasons: [], uncheckable: false };
  }
  let validate: ValidateFunction;
  try {
    validate = compileSiteSchema(siteFormSchema(schema));
  } catch {
    return { reasons: [], uncheckable: true };
  }
  const instance = Object.create(null) as Record<string, unknown>;
  instance[key] = value;
  if (validate(instance)) return { reasons: [], uncheckable: false };
  const secret = opts.secret === true || declaredSecret(schema, key);
  const own = `/${key}`;
  const reasons: string[] = [];
  for (const err of validate.errors ?? []) {
    const sub = err.instancePath.startsWith(own) ? err.instancePath.slice(own.length) : err.instancePath;
    const what = secret
      ? `does not satisfy its declaration (${err.keyword})`
      : `${sub ? sub + ' ' : ''}${err.message ?? 'is invalid'}`;
    if (!reasons.includes(what)) reasons.push(what);
  }
  if (reasons.length === 0) reasons.push('is invalid');
  return { reasons, uncheckable: false };
}

function describeWithheld(w: WithheldBy): string {
  if (w.level === 'computed') {
    return `${nameOf(w)} declares it computed — ObliWAN supplies it at render time, nobody types it`;
  }
  if (w.level === 'bench') {
    return `${nameOf(w)} declares it typed at the bench for one box — it is never stored`;
  }
  return w.level
    ? `${nameOf(w)} declares it at the ${w.level} level`
    : `${nameOf(w)} states no x-obliwan-level for it`;
}

/**
 * Judge a whole site form, without touching a database. Pure, so the harness
 * can prove the line between data entry and authoring on fixtures.
 *
 * All-or-nothing by construction: the caller writes `writes` and `unset` only
 * when `errors` is empty, and every error names its key.
 */
export function validateSiteValues(
  decls: readonly SiteVariableDeclaration[],
  input: {
    entries: readonly { key: string; value: unknown }[];
    unset?: readonly string[];
  },
): SiteValuesVerdict {
  const declared = declaredSiteKeys(decls);
  const errors: SiteValueError[] = [];
  const writes: SiteValuesVerdict['writes'] = [];
  const unset: string[] = [];
  const seen = new Set<string>();
  const entryKeys = new Set(input.entries.map((e) => e.key));
  const unsetKeys = new Set(input.unset ?? []);

  const admissible = (key: string): DeclaredSiteKey | null => {
    if (!VARIABLE_KEY_RE.test(key) || FORBIDDEN_KEYS.has(key)) {
      errors.push({ key, message: 'is not a legal variable name' });
      return null;
    }
    if (seen.has(key)) {
      errors.push({ key, message: 'appears more than once in the request' });
      return null;
    }
    seen.add(key);
    const d = declared.get(key);
    if (!d) {
      errors.push({
        key,
        message:
          'is not declared by any published revision of an active template visible to ' +
          'this tenant — only a declared variable can be set through the site form; ' +
          'declaring a new one is a template author\'s act',
      });
      return null;
    }
    if (!d.siteWritable) {
      errors.push({
        key,
        message:
          `is not opened to the site form: ${d.withheldBy.map(describeWithheld).join(', ')} ` +
          '— only a key every published declaration marks "x-obliwan-level": "site" is ' +
          'typed here; a template author (TEMPLATE_WRITE) can set it for this site through ' +
          GENERIC_SITE_ROUTE,
      });
      return null;
    }
    if (d.secrecyConflict) {
      errors.push({
        key,
        message:
          'is declared secret by some published revisions and not by others (' +
          `${d.declaredBy.map(nameOf).join(', ')}) — a template author must settle it ` +
          'before a site value can be stored',
      });
      return null;
    }
    return d;
  };

  for (const e of input.entries) {
    if (unsetKeys.has(e.key)) {
      seen.add(e.key);
      errors.push({ key: e.key, message: 'is both written and unset in the same request' });
      continue;
    }
    if (isContextFactKey(e.key)) {
      // Before the declaration check, so the refusal names the actual reason
      // rather than "not declared" — and so it is a 422 listing this key, not
      // `assertWritable`'s plain Error from inside the write transaction.
      seen.add(e.key);
      errors.push({
        key: e.key,
        message:
          `names a fact object the render supplies (${CONTEXT_FACT_KEYS.join(', ')}) and cannot ` +
          'be stored as a variable',
      });
      continue;
    }
    const d = admissible(e.key);
    if (!d) continue;

    if (d.secret) {
      if (
        typeof e.value !== 'string' ||
        e.value.length === 0 ||
        e.value.length > SECRET_MAX_LENGTH
      ) {
        errors.push({
          key: e.key,
          message:
            'is declared secret: its value must be a non-empty string of at most ' +
            `${SECRET_MAX_LENGTH} characters`,
        });
        continue;
      }
    } else {
      try {
        assertJsonPure(e.value, `$.${e.key}`);
      } catch (err) {
        // ImpureContextError names the path and the type, never the value.
        errors.push({ key: e.key, message: (err as Error).message });
        continue;
      }
    }

    const typeErrors = checkAgainstDeclarations(decls, d, e.key, e.value);
    if (typeErrors.length > 0) {
      errors.push(...typeErrors);
      continue;
    }
    writes.push({ key: e.key, value: e.value as JsonValue, isSecret: d.secret });
  }

  for (const key of input.unset ?? []) {
    if (entryKeys.has(key)) continue; // already refused above, once
    if (admissible(key)) unset.push(key);
  }

  return errors.length > 0 ? { writes: [], unset: [], errors } : { writes, unset, errors };
}

/**
 * Every published revision of an ACTIVE template visible to the tenant — its
 * own and the shipped library — newest first, which is the order
 * `declaredSiteKeys` expects. Exported for the harness, which renders it to SQL
 * without a database.
 *
 * Archiving a template leaves its revisions `published`, so `r.status` alone
 * would keep them. They are left out on `t.status` instead: archiving is the
 * documented gesture for withdrawing a template, and `render.service` and
 * `assignment.service` both refuse to render an archived one, so its
 * declarations must neither open a key to the form nor constrain what may be
 * typed into it.
 */
export function siteDeclarationsQuery(executor: Knex | Knex.Transaction, tenantId: number) {
  return executor('template_revisions as r')
    .join('templates as t', 't.id', 'r.template_id')
    .where('r.status', 'published')
    .andWhere('t.status', 'active')
    .andWhere(function ownOrLibrary(this: Knex.QueryBuilder) {
      this.where('r.tenant_id', tenantId).orWhereNull('r.tenant_id');
    })
    .orderByRaw('r.published_at desc nulls last, r.id desc')
    .select(
      'r.id as revision_id',
      'r.revision as revision',
      'r.tenant_id as tenant_id',
      'r.var_schema as var_schema',
      't.id as template_id',
      't.name as template_name',
    );
}

export async function loadSiteDeclarations(
  executor: Knex | Knex.Transaction,
  tenantId: number,
): Promise<SiteVariableDeclaration[]> {
  const rows = (await siteDeclarationsQuery(executor, tenantId)) as {
    revision_id: string | number;
    revision: number;
    tenant_id: number | null;
    var_schema: unknown;
    template_id: string | number;
    template_name: string;
  }[];
  // `bigIncrements` ids come back from pg as strings.
  return rows.map((r) => ({
    templateId: Number(r.template_id),
    templateName: r.template_name,
    revisionId: Number(r.revision_id),
    revision: Number(r.revision),
    library: r.tenant_id === null,
    varSchema: (isPlainObject(r.var_schema) ? r.var_schema : {}) as VarSchema,
  }));
}

/**
 * Hold every template and revision row the tenant can see — drafts included —
 * FOR SHARE until the site form's transaction ends. Exported for the harness.
 *
 * WHY: the declarations decide what goes to the vault. Judged on one snapshot
 * and written on another, a revision published in between that newly declares
 * a key `x-obliwan-secret` would see the value typed for it land in the CLEAR
 * `value` column, which every read route of this API returns unredacted. A
 * render refuses such a row, but only once the plaintext is already stored —
 * the very boundary migration 008's decision 6 exists to hold.
 *
 * Publishing and deprecating UPDATE a revision row, archiving UPDATEs a
 * template row; each of those row locks conflicts with FOR SHARE, so each
 * either committed before the declarations are read (under READ COMMITTED the
 * next statement sees it) or waits until the values are written.
 *
 * WHAT IT DOES NOT COVER: a revision INSERTED after the lock is taken is not
 * among the locked rows, so a draft created AND published inside the few
 * milliseconds this transaction lasts would still slip through. Closing that
 * too needs a lock `publishRevision` also takes, in `version.service.ts`.
 *
 * No `?` in this text: knex would rewrite it into a positional binding.
 */
export const SITE_FORM_LOCK_SQL = `
  select r.id
    from template_revisions r
    join templates t on t.id = r.template_id
   where r.tenant_id = :tenantId or r.tenant_id is null
     for share of r, t
`;

// ============================================================================
// Public API
// ============================================================================

/** Audit columns migration 008 puts on `config_variables`. */
export interface VariableMeta {
  description?: string | null;
  updatedBy?: number | null;
}

/** A device as the resolver needs it. `site_id` / `site_name` are set only
 *  when the site belongs to the SAME tenant as the device. */
interface DeviceTarget {
  id: number;
  name: string;
  group_id: number | null;
  site_id: number | null;
  site_name: string | null;
}

/** Read a device, scoped by tenant, with its site joined on the same tenant:
 *  `devices.site_id` has no tenant-aware constraint of its own, and a site id
 *  pointing into another tenant must read as "no site" here exactly as the
 *  chain query treats it. Non-throwing. */
async function readDevice(
  executor: Knex | Knex.Transaction,
  tenantId: number,
  deviceId: number,
): Promise<DeviceTarget | undefined> {
  return (await executor('devices as d')
    .leftJoin('sites as s', function sameTenantSite(this: Knex.JoinClause) {
      this.on('s.id', '=', 'd.site_id').andOn('s.tenant_id', '=', 'd.tenant_id');
    })
    .where('d.id', deviceId)
    .andWhere('d.tenant_id', tenantId)
    .first(
      'd.id as id',
      'd.name as name',
      'd.group_id as group_id',
      's.id as site_id',
      's.name as site_name',
    )) as DeviceTarget | undefined;
}

/** Look up a device, scoped by tenant. A device id belonging to another tenant
 *  does not exist as far as this service is concerned. */
async function loadDevice(
  executor: Knex | Knex.Transaction,
  tenantId: number,
  deviceId: number,
): Promise<DeviceTarget> {
  const row = await readDevice(executor, tenantId, deviceId);
  if (!row) throw new Error(`Device #${deviceId} does not exist in tenant #${tenantId}.`);
  return row;
}

/** The report target of a device: its own group unless the caller names one
 *  (then the device is read non-throwing, as before), its site read from its
 *  own row on the same tenant. */
async function deviceTarget(
  executor: Knex | Knex.Transaction,
  tenantId: number,
  deviceId: number,
  groupIdOverride: number | null | undefined,
): Promise<ReportTarget> {
  let dev: DeviceTarget | undefined;
  let groupId: number | null;
  if (groupIdOverride !== undefined) {
    groupId = groupIdOverride;
    dev = await readDevice(executor, tenantId, deviceId);
  } else {
    dev = await loadDevice(executor, tenantId, deviceId);
    groupId = dev.group_id;
  }
  return {
    groupId,
    siteId: dev?.site_id ?? null,
    siteName: dev?.site_name ?? null,
    deviceId,
    deviceName: dev?.name ?? null,
  };
}

/** Same rule for a site: another tenant's site does not exist. */
async function loadSite(
  executor: Knex | Knex.Transaction,
  tenantId: number,
  siteId: number,
): Promise<{ id: number; code: string; name: string }> {
  const row = (await executor('sites')
    .where({ id: siteId, tenant_id: tenantId })
    .first('id', 'code', 'name')) as { id: number; code: string; name: string } | undefined;
  if (!row) throw new Error(`Site #${siteId} does not exist in tenant #${tenantId}.`);
  return row;
}

/** A group named by the CALLER (the bench path) must be this tenant's. The
 *  chain query would ignore a foreign one silently, and "no group values" on a
 *  router about to be provisioned is a configuration with holes nobody saw. */
async function assertGroupInTenant(
  executor: Knex | Knex.Transaction,
  tenantId: number,
  groupId: number,
): Promise<void> {
  const row = await executor('device_groups').where({ id: groupId, tenant_id: tenantId }).first('id');
  if (!row) throw new Error(`Group #${groupId} does not exist in tenant #${tenantId}.`);
}

/** A revision's `var_schema`, tenant-scoped — library revisions included,
 *  since a tenant may render a library template. Reads the schema and nothing
 *  else: whether the revision may be RENDERED (draft, quarantined…) is the
 *  renderer's decision, not the variable resolver's. */
async function loadRevisionSchema(
  executor: Knex | Knex.Transaction,
  tenantId: number,
  revisionId: number,
): Promise<VarSchema | null> {
  const row = (await executor('template_revisions')
    .where('id', revisionId)
    .andWhere(function ownOrLibrary(this: Knex.QueryBuilder) {
      this.where('tenant_id', tenantId).orWhereNull('tenant_id');
    })
    .first('var_schema')) as { var_schema: unknown } | undefined;
  if (!row) {
    throw new Error(`Template revision #${revisionId} does not exist in tenant #${tenantId}.`);
  }
  return (row.var_schema ?? null) as VarSchema | null;
}

/** Whom a report is about. */
interface ReportTarget {
  groupId: number | null;
  siteId: number | null;
  siteName: string | null;
  deviceId: number | null;
  deviceName: string | null;
}

/** The one place a `VariableReport` is assembled, for a device or a site. */
async function buildReport(
  executor: Knex | Knex.Transaction,
  tenantId: number,
  varSchema: VarSchema | null,
  t: ReportTarget,
  supplied: RenderTimeValues = {},
): Promise<VariableReport> {
  return (await assembleReport(executor, tenantId, varSchema, t, supplied)).report;
}

/** `buildReport`, plus the facts the revision does not declare — which the
 *  caller hands to the context as `extra`. */
async function assembleReport(
  executor: Knex | Knex.Transaction,
  tenantId: number,
  varSchema: VarSchema | null,
  t: ReportTarget,
  supplied: RenderTimeValues,
): Promise<{ report: VariableReport; undeclaredFacts: Record<string, JsonValue> }> {
  const rows = await chainRows(executor, tenantId, {
    groupId: t.groupId,
    deviceId: t.deviceId,
    siteId: t.siteId,
  });
  const { variables, plaintexts, rejected } = fold(tenantId, rows);
  // Render-time values BEFORE the schema pass: what the caller supplied is
  // typed and counts as resolved; what it did not is reported missing at its
  // own level. Run with an empty `supplied` too (the device path, the
  // inspection views), so a stored row never stands in for a computed key.
  const overlay = applyRenderTimeValues(tenantId, varSchema, variables, plaintexts, supplied);
  const { missing, typeErrors } = applySchema(varSchema, variables, plaintexts, new Set(overlay.withheld));
  typeErrors.unshift(...overlay.errors);
  if (t.deviceId === null && t.siteId !== null) {
    // The bench: the router has no `devices` row, so "define it at the device
    // level" — `expectedLevel`'s default when the author stated no level, or
    // what the author wrote — would name a level this target does not have.
    // Its site is the narrowest level it inherits from, so that is where the
    // error must send the operator.
    for (const m of missing) if (m.expectedScope === 'device') m.expectedScope = 'site';
  }

  const bad = missing.length > 0 || typeErrors.length > 0 || rejected.length > 0;
  const chain = bad ? await describeChain(executor, tenantId, t) : [];

  return {
    report: {
      tenantId,
      deviceId: t.deviceId,
      deviceName: t.deviceName,
      groupId: t.groupId,
      siteId: t.siteId,
      siteName: t.siteName,
      chain,
      variables,
      missing,
      typeErrors,
      rejected,
      shadowed: overlay.shadowed,
      unusedComputed: overlay.unusedComputed,
      ok: !bad,
    },
    undeclaredFacts: overlay.undeclaredFacts,
  };
}

/** "device #12 ("Mik-Central")", or "site #4 ("Paris")" on the bench path. */
function targetLabel(r: {
  deviceId: number | null;
  deviceName: string | null;
  siteId: number | null;
  siteName: string | null;
}): string {
  if (r.deviceId !== null) {
    return r.deviceName ? `device #${r.deviceId} ("${r.deviceName}")` : `device #${r.deviceId}`;
  }
  if (r.siteId !== null) {
    return r.siteName ? `site #${r.siteId} ("${r.siteName}")` : `site #${r.siteId}`;
  }
  return 'this target';
}

/**
 * Report -> render context. The single body behind `buildRenderContext` and
 * `buildRenderContextForSite`, so the template-execution boundary below exists once.
 */
async function contextFromReport(
  executor: Knex | Knex.Transaction,
  report: VariableReport,
  mode: 'redacted' | 'secrets',
  extra: Record<string, unknown> | undefined,
  supplied: RenderTimeValues = {},
): Promise<RenderContext> {
  if (!report.ok) {
    throw new VariableResolutionError(
      formatResolutionError(report),
      report.tenantId,
      report.deviceId,
      report.missing,
      report.typeErrors,
      report.chain,
      report.siteId,
    );
  }

  // The plaintexts are re-read here rather than carried out of the report: a
  // plaintext is never a field of a report that a caller might log or persist.
  // A render-time secret is re-read from the caller's own map for the same
  // reason, and from nowhere else: the database never held it.
  let plaintexts = new Map<string, string>();
  if (mode === 'secrets') {
    const rows = await chainRows(executor, report.tenantId, {
      groupId: report.groupId,
      deviceId: report.deviceId,
      siteId: report.siteId,
    });
    plaintexts = fold(report.tenantId, rows).plaintexts;
    for (const [key, v] of Object.entries(report.variables)) {
      if (!v.isSecret || (v.source !== 'computed' && v.source !== 'bench')) continue;
      const map = supplied[v.source];
      const raw =
        map && Object.prototype.hasOwnProperty.call(map, key) ? (map as Record<string, unknown>)[key] : undefined;
      if (typeof raw === 'string' && raw.length > 0) plaintexts.set(key, raw);
      else plaintexts.delete(key);
    }
  }

  // Null-prototype for the same reason `fold` uses one: a variable legitimately
  // named `toString` must not read as "already present" through the prototype.
  // `jsonClone` at the end hands the worker an ordinary object, built from
  // own properties only.
  const context: Record<string, JsonValue> = Object.create(null) as Record<string, JsonValue>;
  const secretKeys: string[] = [];
  for (const [key, v] of Object.entries(report.variables)) {
    if (v.isSecret) {
      secretKeys.push(key);
      if (mode === 'secrets') {
        const p = plaintexts.get(key);
        if (p === undefined) {
          // The level the secret was resolved FROM: where it is stored is where
          // it has to be fixed. A fixed 'device' would be wrong for a secret set
          // at a group or a site, and names a level a bench target does not have.
          const expectedScope: VariableLevel =
            v.source !== 'default' ? v.source : report.deviceId === null ? 'site' : 'device';
          throw new VariableResolutionError(
            `Secret variable "${key}" (set at ${v.sourceName}) could not be read ` +
              (v.source === 'computed' || v.source === 'bench'
                ? 'from the values supplied to this render'
                : 'from the vault') +
              ` for ${targetLabel(report)}.`,
            report.tenantId,
            report.deviceId,
            [{ key, expectedScope, reason: 'secret-declared-but-absent' }],
            [],
            report.chain,
            report.siteId,
          );
        }
        context[key] = p;
        continue;
      }
    }
    context[key] = v.value;
  }

  if (extra) {
    for (const [k, v] of Object.entries(extra)) {
      if (!VARIABLE_KEY_RE.test(k) || FORBIDDEN_KEYS.has(k)) {
        throw new ImpureContextError(`Illegal context key "${k}" in \`extra\`.`, `$.${k}`);
      }
      if (k in context) {
        throw new Error(
          `\`extra\` key "${k}" collides with a resolved variable — refusing to let ` +
            'render facts silently shadow an operator-set variable.',
        );
      }
      context[k] = v as JsonValue;
    }
  }

  // The template-execution boundary. Prove, then re-materialise through JSON so no object
  // identity from this realm survives into the worker.
  assertJsonPure(context);
  const pure = jsonClone(context);

  return { context: pure, mode, variables: report.variables, secretKeys, report };
}

// ── The bench path: a router that has no `devices` row yet ─────────────────

export interface ResolveForSiteOptions {
  /** Mandatory and without default, as everywhere in this file
   *  — a missing tenant must fail to compile. */
  tenantId: number;
  /** Must belong to `tenantId`, or the call throws "does not exist". */
  siteId: number;
  /** The group the router WILL be filed under, when the caller already knows
   *  it. Must belong to `tenantId`. Omitted or null: no group level. */
  groupId?: number | null;
  /** The revision whose `var_schema` types the answer (own or library). */
  revisionId: number;
  /** Render-time values (see `RenderTimeValues`). Omitted: none supplied, so
   *  a required `computed` / `bench` key is reported missing — which is what
   *  an inspection of a site with no allocation and no box should say. */
  computed?: Record<string, unknown>;
  bench?: Record<string, unknown>;
  facts?: Record<string, unknown>;
  executor?: Knex | Knex.Transaction;
}

function suppliedOf(opts: RenderTimeValues): RenderTimeValues {
  return { computed: opts.computed, bench: opts.bench, facts: opts.facts };
}

/** Undeclared facts and the caller's own `extra`, merged — a key in both is a
 *  caller bug, refused rather than silently resolved one way. */
function mergeExtra(
  facts: Record<string, JsonValue>,
  extra: Record<string, unknown> | undefined,
): Record<string, unknown> {
  const out: Record<string, unknown> = { ...facts };
  for (const [k, v] of ownEntries(extra)) {
    if (Object.prototype.hasOwnProperty.call(out, k)) {
      throw new Error(`\`extra\` key "${k}" is also supplied as a render-time fact.`);
    }
    out[k] = v;
  }
  return out;
}

async function siteTarget(
  executor: Knex | Knex.Transaction,
  opts: { tenantId: number; siteId: number; groupId?: number | null },
): Promise<ReportTarget> {
  const site = await loadSite(executor, opts.tenantId, opts.siteId);
  const groupId = opts.groupId ?? null;
  if (groupId !== null) await assertGroupInTenant(executor, opts.tenantId, groupId);
  return { groupId, siteId: site.id, siteName: site.name, deviceId: null, deviceName: null };
}

/**
 * Resolve every variable for a router that does NOT EXIST in the fleet yet —
 * the provisioning bench, where the box on the table is identified by the site
 * it is being prepared for.
 *
 * Walks instance -> global -> tenant -> group (when `groupId` is given) ->
 * site, and never the device level: there is no device. Render-time values
 * (`computed`, `bench`, `facts`) are laid over it when supplied. Same report
 * shape as
 * `resolveForDevice`, with `deviceId` and `deviceName` null. Non-throwing on a
 * missing variable (it is the INSPECTION view); throws only on a target that
 * is not this tenant's — site, group or revision — with the words
 * "does not exist in tenant", which the controllers map to a 404.
 *
 * Once the router is enrolled and filed under the same site, `resolveForDevice`
 * walks the same levels plus its own device overrides, so a render made on the
 * bench and the first render made in the fleet agree unless somebody set a
 * device override in between.
 */
export async function resolveForSite(opts: ResolveForSiteOptions): Promise<VariableReport> {
  return (await assembleSite(opts)).report;
}

async function assembleSite(
  opts: ResolveForSiteOptions,
): Promise<{ report: VariableReport; undeclaredFacts: Record<string, JsonValue> }> {
  const executor = opts.executor ?? db;
  const target = await siteTarget(executor, opts);
  const varSchema = await loadRevisionSchema(executor, opts.tenantId, opts.revisionId);
  return assembleReport(executor, opts.tenantId, varSchema, target, suppliedOf(opts));
}

/**
 * `buildRenderContext` for the bench path: THROWS rather than render a hole,
 * and returns a context proven pure JSON. Same two modes, same rule — the
 * 'secrets' context is IN MEMORY ONLY, on the path vault -> equipment.
 */
export async function buildRenderContextForSite(
  opts: ResolveForSiteOptions & {
    mode?: 'redacted' | 'secrets';
    /** Facts about the router on the bench (model, MAC…). Validated exactly
     *  like the variables, and refused if one shadows a resolved variable. */
    extra?: Record<string, unknown>;
  },
): Promise<RenderContext> {
  const executor = opts.executor ?? db;
  const { report, undeclaredFacts } = await assembleSite(opts);
  return contextFromReport(
    executor,
    report,
    opts.mode ?? 'redacted',
    mergeExtra(undeclaredFacts, opts.extra),
    suppliedOf(opts),
  );
}

/**
 * The bench render's two contexts from ONE report: the REDACTED one the body
 * is rendered with (secrets are `__OBLIWAN_SECRET_<KEY>__`), and — only when
 * `withSecrets` — the 'secrets' one whose plaintexts the caller splices into
 * that body afterwards (`siteRender.service.ts`). One report, so both contexts
 * describe the same resolution: the same keys, the same secrecy, the same
 * shadowing. The secrets context is IN MEMORY ONLY.
 */
export async function buildSiteRenderContexts(
  opts: ResolveForSiteOptions & { withSecrets: boolean; extra?: Record<string, unknown> },
): Promise<{ redacted: RenderContext; secrets: RenderContext | null }> {
  const executor = opts.executor ?? db;
  const { report, undeclaredFacts } = await assembleSite(opts);
  const extra = mergeExtra(undeclaredFacts, opts.extra);
  const supplied = suppliedOf(opts);
  const redacted = await contextFromReport(executor, report, 'redacted', extra, supplied);
  const secrets = opts.withSecrets
    ? await contextFromReport(executor, report, 'secrets', extra, supplied)
    : null;
  return { redacted, secrets };
}

/** The STORED plaintext secrets that apply to a site, IN MEMORY ONLY — what
 *  `assertNoStoredSecretInRender` scans a bench render against before it is
 *  kept or shipped. */
export async function loadSecretsForSite(opts: {
  tenantId: number;
  siteId: number;
  groupId?: number | null;
  executor?: Knex | Knex.Transaction;
}): Promise<{ key: string; plaintext: string }[]> {
  const executor = opts.executor ?? db;
  const t = await siteTarget(executor, opts);
  const rows = await chainRows(executor, opts.tenantId, {
    groupId: t.groupId,
    deviceId: null,
    siteId: t.siteId,
  });
  return [...fold(opts.tenantId, rows).plaintexts].map(([key, plaintext]) => ({ key, plaintext }));
}

/** The STORED values that apply to a site (instance -> tenant -> group ->
 *  site), folded like a render's chain: the clear ones as values, the secret
 *  ones as plaintexts IN MEMORY ONLY. For a server-side caller that
 *  needs a few named keys without a template revision (the infra concentrator
 *  account, services/infraConcentrator). */
export async function loadStoredValuesForSite(opts: {
  tenantId: number;
  siteId: number;
  groupId?: number | null;
  executor?: Knex | Knex.Transaction;
}): Promise<{ values: Record<string, JsonValue>; plaintexts: Map<string, string> }> {
  const executor = opts.executor ?? db;
  const t = await siteTarget(executor, opts);
  const rows = await chainRows(executor, opts.tenantId, { groupId: t.groupId, deviceId: null, siteId: t.siteId });
  const folded = fold(opts.tenantId, rows);
  const values: Record<string, JsonValue> = Object.create(null) as Record<string, JsonValue>;
  for (const [key, v] of Object.entries(folded.variables)) {
    if (!v.isSecret) values[key] = v.value;
  }
  return { values, plaintexts: folded.plaintexts };
}

/**
 * The two columns of migration 008's decision 6, for one value: a secret goes
 * to `secret_enc` with a NULL `value`, a clear value goes to `value` with a
 * NULL `secret_enc`. Pure apart from the vault, so the harness can prove the
 * routing; `_write` is its only production caller.
 */
export function variableColumns(
  value: JsonValue,
  isSecret: boolean,
): { value: string | null; secret_enc: string | null; is_secret: boolean } {
  return {
    value: isSecret ? null : JSON.stringify(value),
    secret_enc: isSecret ? encrypt(value as string) : null,
    is_secret: isSecret,
  };
}

export const variableResolver = {
  // ── Inspection (never throws on a missing variable) ──────────────────────

  /**
   * Resolve every variable that applies to a device, in REDACTED form.
   *
   * `tenantId` first and mandatory. `groupId` may be passed
   * by a caller that already has it (`render.service` walking a rollout) to
   * save the device lookup; when omitted it is read from `devices`, scoped by
   * tenant. The SITE is never taken from the caller: the chain query reads it
   * from the device's own `site_id`.
   *
   * Cost: one query for the whole chain, one for the device row, and one for
   * the chain DESCRIPTION only when something is wrong.
   */
  async resolveForDevice(
    tenantId: number,
    deviceId: number,
    varSchema: VarSchema | null = null,
    opts: {
      groupId?: number | null;
      executor?: Knex | Knex.Transaction;
      /** Render-time values the CALLER holds for this device (the fleet render
       *  of a bench-prepared router, `render.service`). Omitted: none, so a
       *  revision's `computed` / `bench` keys are reported missing. */
      renderTime?: RenderTimeValues;
    } = {},
  ): Promise<VariableReport> {
    const executor = opts.executor ?? db;
    const target = await deviceTarget(executor, tenantId, deviceId, opts.groupId);
    return buildReport(executor, tenantId, varSchema, target, opts.renderTime ?? {});
  },

  /** See the exported `resolveForSite` — the bench path. */
  resolveForSite,

  /**
   * The group-level view the variables UI needs: what a group INHERITS
   * (instance -> global -> tenant -> ancestors, self excluded) and what it
   * OVERRIDES.
   * Mirrors `settingsService.resolveForGroup`. No site level: a group spans
   * sites, so no single site's values belong in its view.
   */
  async resolveForGroup(
    tenantId: number,
    groupId: number,
    varSchema: VarSchema | null = null,
  ): Promise<{ inherited: ResolvedVariables; overrides: ResolvedVariables }> {
    const rows = await chainRows(db, tenantId, { groupId, deviceId: null, siteId: null });
    // depth 0 is the group itself; the inherited view stops at its parent.
    const inheritedRows = rows.filter((r) => r.scope !== 'group' || (r.depth ?? 0) > 0);
    const ownRows = rows.filter((r) => r.scope === 'group' && (r.depth ?? -1) === 0);
    const inherited = fold(tenantId, inheritedRows);
    applySchema(varSchema, inherited.variables, inherited.plaintexts);
    return {
      inherited: inherited.variables,
      overrides: fold(tenantId, ownRows).variables,
    };
  },

  /** Instance + global + tenant only — the levels that apply to a whole
   *  customer (the instance level to every customer at once). */
  async resolveForTenant(
    tenantId: number,
    varSchema: VarSchema | null = null,
  ): Promise<ResolvedVariables> {
    const rows = await chainRows(db, tenantId, { groupId: null, deviceId: null, siteId: null });
    const { variables, plaintexts } = fold(tenantId, rows);
    applySchema(varSchema, variables, plaintexts);
    return variables;
  },

  // ── The render path (THROWS rather than render a hole) ───────────────────

  /**
   * Build the context handed to the Nunjucks worker.
   *
   * This and `buildRenderContextForSite` are the ONLY functions that produce a
   * render context — both through `contextFromReport` — and they THROW —
   * `VariableResolutionError` — when a required variable did not resolve, when
   * a value does not match its declared type, or when a row was rejected. A
   * template that renders `interface=` with nothing after it is a config that
   * either fails on the router or, worse, succeeds and means something else.
   *
   * `mode`:
   *   'redacted' (default) — secrets are placeholders. This context produces
   *       the body stored in `config_renders.body`, the `ncm_desired`, the diff
   *       and the plan: everything that is persisted or displayed.
   *   'secrets' — secrets are plaintext. IN MEMORY ONLY, on the path
   *       vault -> equipment. The caller must not store, log, cache or
   *       put into a `PlanOp` anything derived from it, and must run
   *       `assertNoPlaintextSecret()` on anything it is tempted to keep.
   *
   * What comes back is proven pure JSON (`assertJsonPure` + `jsonClone`): no
   * live object, no function, no prototype, no `__proto__` key. That is this
   * file's half of the template-execution boundary.
   */
  async buildRenderContext(
    tenantId: number,
    deviceId: number,
    varSchema: VarSchema | null,
    opts: {
      groupId?: number | null;
      mode?: 'redacted' | 'secrets';
      /** Extra device facts (name, model, os version...). Validated for JSON
       *  purity exactly like the variables — a live knex row must not cross. */
      extra?: Record<string, unknown>;
      executor?: Knex | Knex.Transaction;
      /** As in `resolveForDevice`. Undeclared `site` / `box` facts join
       *  `extra`, exactly as on the bench path. */
      renderTime?: RenderTimeValues;
    } = {},
  ): Promise<RenderContext> {
    const executor = opts.executor ?? db;
    const supplied = opts.renderTime ?? {};
    const target = await deviceTarget(executor, tenantId, deviceId, opts.groupId);
    const { report, undeclaredFacts } = await assembleReport(executor, tenantId, varSchema, target, supplied);
    return contextFromReport(
      executor,
      report,
      opts.mode ?? 'redacted',
      mergeExtra(undeclaredFacts, opts.extra),
      supplied,
    );
  },

  /** See the exported `buildRenderContextForSite` — the bench path. */
  buildRenderContextForSite,

  /**
   * The plaintext secrets for a device, IN MEMORY ONLY. Kept out of the context
   * so a caller has to ask for them explicitly, and so
   * `assertNoStoredSecretInRender` has something to scan a render against
   * before anything is persisted.
   */
  async loadSecrets(
    tenantId: number,
    deviceId: number,
    opts: { groupId?: number | null; executor?: Knex | Knex.Transaction } = {},
  ): Promise<{ key: string; plaintext: string }[]> {
    const executor = opts.executor ?? db;
    const groupId =
      opts.groupId !== undefined
        ? opts.groupId
        : (await loadDevice(executor, tenantId, deviceId)).group_id;
    // No site lookup: on the device path the chain query reads the site from
    // the device's own row, which is the only source it may come from.
    const rows = await chainRows(executor, tenantId, { groupId, deviceId, siteId: null });
    return [...fold(tenantId, rows).plaintexts].map(([key, plaintext]) => ({ key, plaintext }));
  },

  /** See the exported `loadSecretsForSite` — the bench path. */
  loadSecretsForSite,

  // ── Raw CRUD ─────────────────────────────────────────────────────────────

  /** Every variable set AT a level (no inheritance), redacted. */
  async getByScope(
    tenantId: number,
    scope: VariableScope,
    scopeId: number | null,
  ): Promise<ResolvedVariables> {
    const rows = (await db('config_variables')
      .where({ tenant_id: tenantId, scope, scope_id: scopeId })
      .select('key', 'value', 'is_secret', 'secret_enc')) as {
      key: string;
      value: unknown;
      is_secret: boolean;
      secret_enc: string | null;
    }[];
    return fold(
      tenantId,
      rows.map((r) => ({
        scope,
        rank: VARIABLE_SCOPE_RANK[scope],
        depth: null,
        src_id: scopeId,
        src_name: null,
        key: r.key,
        value: r.value,
        is_secret: r.is_secret,
        secret_enc: r.secret_enc,
      })),
    ).variables;
  },

  /**
   * Write one variable. A secret is encrypted here and NEVER stored in clear;
   * the plaintext is not returned, not logged and not echoed in an error.
   */
  async set(
    tenantId: number,
    scope: VariableScope,
    scopeId: number | null,
    key: string,
    value: JsonValue,
    isSecret = false,
    meta: VariableMeta = {},
  ): Promise<void> {
    await db.transaction((trx) =>
      this._write(trx, tenantId, scope, scopeId, key, value, isSecret, meta),
    );
  },

  /**
   * Validate EVERYTHING first, then write the lot in ONE
   * transaction. A half-applied variables form leaves an operator with no way
   * to tell which half took.
   */
  async setBulk(
    tenantId: number,
    scope: VariableScope,
    scopeId: number | null,
    entries: { key: string; value: JsonValue; isSecret?: boolean; meta?: VariableMeta }[],
  ): Promise<void> {
    for (const e of entries) assertWritable(scope, scopeId, e.key, e.value, e.isSecret ?? false);
    await db.transaction(async (trx) => {
      for (const e of entries) {
        await this._write(
          trx,
          tenantId,
          scope,
          scopeId,
          e.key,
          e.value,
          e.isSecret ?? false,
          e.meta ?? {},
        );
      }
    });
  },

  /**
   * The two-column write of migration 008's decision 6 (`variableColumns`).
   * `merge()` sets BOTH columns every time, because flipping a variable from
   * clear to secret (or back) must not leave the other column populated — the
   * CHECK would reject it, which is the correct outcome, but only if the
   * update actually names both columns.
   */
  async _write(
    executor: Knex | Knex.Transaction,
    tenantId: number,
    scope: VariableScope,
    scopeId: number | null,
    key: string,
    value: JsonValue,
    isSecret: boolean,
    meta: VariableMeta = {},
  ): Promise<void> {
    await upsertVariable(executor, tenantId, scope, scopeId, key, value, isSecret, meta);
  },

  async remove(
    tenantId: number,
    scope: VariableScope,
    scopeId: number | null,
    key: string,
  ): Promise<boolean> {
    const n = await db('config_variables')
      .where({ tenant_id: tenantId, scope, scope_id: scopeId, key })
      .del();
    return n > 0;
  },

  // ── The instance level (platform administrators only) ────────────────────
  //
  // No `tenantId` parameter, on purpose: an instance row belongs to no tenant,
  // and taking one would invite a caller to believe it scopes something. The
  // route in front of these is `requireRole('admin')`, never a capability —
  // a value written here reaches every tenant's render at once.

  /**
   * Every instance value, redacted. `viewerTenantId` only keys the secret
   * FINGERPRINTS (they are per tenant, `tenantFingerprintKey`), so the
   * fingerprint a viewer reads here is the one their own resolved views show.
   */
  async getInstance(viewerTenantId: number): Promise<ResolvedVariables> {
    const rows = (await db('config_variables')
      .whereNull('tenant_id')
      .andWhere({ scope: INSTANCE_SCOPE })
      .whereNull('scope_id')
      .select('key', 'value', 'is_secret', 'secret_enc')) as {
      key: string;
      value: unknown;
      is_secret: boolean;
      secret_enc: string | null;
    }[];
    return fold(
      viewerTenantId,
      rows.map((r) => ({
        scope: INSTANCE_SCOPE,
        rank: VARIABLE_SCOPE_RANK.instance,
        depth: null,
        src_id: null,
        src_name: null,
        key: r.key,
        value: r.value,
        is_secret: r.is_secret,
        secret_enc: r.secret_enc,
      })),
    ).variables;
  },

  async setInstance(
    key: string,
    value: JsonValue,
    isSecret = false,
    meta: VariableMeta = {},
  ): Promise<void> {
    await db.transaction((trx) =>
      upsertVariable(trx, null, INSTANCE_SCOPE, null, key, value, isSecret, meta),
    );
  },

  /** All or nothing, like `setBulk`. */
  async setInstanceBulk(
    entries: { key: string; value: JsonValue; isSecret?: boolean; meta?: VariableMeta }[],
  ): Promise<void> {
    for (const e of entries) assertWritable(INSTANCE_SCOPE, null, e.key, e.value, e.isSecret ?? false);
    await db.transaction(async (trx) => {
      for (const e of entries) {
        await upsertVariable(
          trx, null, INSTANCE_SCOPE, null, e.key, e.value, e.isSecret ?? false, e.meta ?? {},
        );
      }
    });
  },

  async removeInstance(key: string): Promise<boolean> {
    const n = await db('config_variables')
      .whereNull('tenant_id')
      .andWhere({ scope: INSTANCE_SCOPE, key })
      .whereNull('scope_id')
      .del();
    return n > 0;
  },

  // ── The site form (SITE_VARIABLES_WRITE) ─────────────────────────────────

  /**
   * Everything a site form needs: the site, what is set AT the site (redacted),
   * and every key a published revision of an active template declares, with
   * its schema, its label and `siteWritable` — the keys the PUT will refuse
   * are listed too, with `withheldBy` saying why, so a form can show them
   * read-only instead of failing on submit.
   * Throws "does not exist in tenant" on another tenant's site.
   */
  async describeSiteForm(tenantId: number, siteId: number): Promise<SiteVariableForm> {
    const site = await loadSite(db, tenantId, siteId);
    const values = await this.getByScope(tenantId, 'site', siteId);
    const declared = [...declaredSiteKeys(await loadSiteDeclarations(db, tenantId)).values()]
      .sort((a, b) => (a.key < b.key ? -1 : a.key > b.key ? 1 : 0));
    return { site: { id: site.id, code: site.code, name: site.name }, values, declared };
  },

  /**
   * Write a site form, ALL OR NOTHING: every entry is judged first
   * (`validateSiteValues`) and the lot is written only when none was refused;
   * otherwise `SiteVariablesRefusedError` lists every refused key and nothing
   * is written. Secrecy comes from the declaration.
   *
   * Judged and written inside ONE transaction, against declarations held by
   * `SITE_FORM_LOCK_SQL` for its duration: the declarations decide what goes
   * to the vault, and a verdict reached on one view of them must not be
   * written under another (see that constant for the race this closes, and
   * the narrower one it does not).
   *
   * This is the entry point for anything that fills site values in bulk — the
   * account manager's form, and a bulk site import — so the declared-key,
   * opt-in and type rules cannot be skipped by calling the service instead of
   * the route.
   */
  async setSiteValues(
    tenantId: number,
    siteId: number,
    input: { entries: readonly { key: string; value: unknown }[]; unset?: readonly string[] },
    meta: VariableMeta = {},
  ): Promise<{ written: string[]; unset: string[] }> {
    return db.transaction(async (trx) => {
      // The site is the scope of every row about to be written, and
      // `scope_id` carries no foreign key.
      await loadSite(trx, tenantId, siteId);
      await trx.raw(SITE_FORM_LOCK_SQL, { tenantId });
      const verdict = validateSiteValues(await loadSiteDeclarations(trx, tenantId), input);
      // Thrown inside the transaction: nothing has been written yet, knex rolls
      // back and rejects with this very error, which the controller turns into
      // a 422 listing every refused key.
      if (verdict.errors.length > 0) throw new SiteVariablesRefusedError(verdict.errors);

      for (const w of verdict.writes) {
        await this._write(trx, tenantId, 'site', siteId, w.key, w.value, w.isSecret, meta);
      }
      if (verdict.unset.length > 0) {
        await trx('config_variables')
          .where({ tenant_id: tenantId, scope: 'site', scope_id: siteId })
          .whereIn('key', verdict.unset)
          .del();
      }
      return { written: verdict.writes.map((w) => w.key), unset: verdict.unset };
    });
  },
};

// ============================================================================
// Write-side invariants
// ============================================================================

/**
 * The conflict target of an upsert at `scope`, naming the partial unique
 * index's WHERE clause (PostgreSQL cannot infer a partial index from a bare
 * column list). Exported for the harness. No `?` in any of the three: knex
 * would rewrite it into a positional binding.
 *
 *   instance   `(key) WHERE scope = 'instance'`  — migration 038's index; the
 *              unscoped index below cannot hold an instance row to one per key,
 *              because its `tenant_id` is NULL and PostgreSQL 16 is NULLS
 *              DISTINCT.
 *   unscoped   `(tenant_id, scope, key) WHERE scope_id IS NULL` (global, tenant)
 *   scoped     `(tenant_id, scope, scope_id, key) WHERE scope_id IS NOT NULL`
 */
export function upsertConflictTarget(scope: StoredVariableScope, scopeId: number | null): string {
  if (scope === INSTANCE_SCOPE) return "(key) WHERE scope = 'instance'";
  return scopeId === null
    ? '(tenant_id, scope, key) WHERE scope_id IS NULL'
    : '(tenant_id, scope, scope_id, key) WHERE scope_id IS NOT NULL';
}

/**
 * The two-column write of migration 008's decision 6, for every stored level.
 * `tenantId` is null EXACTLY for the instance level — migration 038's CHECK
 * says the same, and this refuses first so the caller gets a sentence rather
 * than a constraint name.
 */
async function upsertVariable(
  executor: Knex | Knex.Transaction,
  tenantId: number | null,
  scope: StoredVariableScope,
  scopeId: number | null,
  key: string,
  value: JsonValue,
  isSecret: boolean,
  meta: VariableMeta,
): Promise<void> {
  if ((scope === INSTANCE_SCOPE) !== (tenantId === null)) {
    throw new Error(
      scope === INSTANCE_SCOPE
        ? 'Scope "instance" belongs to no tenant: it is written with a null tenant.'
        : `Scope "${scope}" requires a tenant.`,
    );
  }
  // A key that a published revision of an active template declares
  // `x-obliwan-secret` is a secret at EVERY level. The site writer already takes
  // secrecy from the declaration (rule 4 of its box above); the other levels
  // took the caller's checkbox, so an unticked box put a fleet password in the
  // clear column and on screen — and every render then refused it ("declared
  // secret … stored in clear"). The declaration wins here too, in one
  // direction only: it can route a value to the vault, never a secret to clear.
  if (!isSecret && (await isDeclaredSecretAnywhere(executor, key))) isSecret = true;
  assertWritable(scope, scopeId, key, value, isSecret);
  const columns = {
    ...variableColumns(value, isSecret),
    description: meta.description ?? null,
    updated_by: meta.updatedBy ?? null,
    updated_at: new Date(),
  };
  await executor('config_variables')
    .insert({ tenant_id: tenantId, scope, scope_id: scopeId, key, ...columns })
    .onConflict(db.raw(upsertConflictTarget(scope, scopeId)))
    .merge(columns);
}

/** Whether any published revision of an active template, of any tenant or
 *  the library, declares `key` secret. Any tenant on purpose: an instance
 *  value reaches every tenant's renders, and a secret is never less secret
 *  because the template that says so belongs to somebody else. */
async function isDeclaredSecretAnywhere(
  executor: Knex | Knex.Transaction,
  key: string,
): Promise<boolean> {
  const row = await executor('template_revisions as r')
    .join('templates as t', 't.id', 'r.template_id')
    .where('r.status', 'published')
    .andWhere('t.status', 'active')
    .whereRaw("(r.var_schema -> 'properties' -> ? ->> 'x-obliwan-secret') = 'true'", [key])
    .first('r.id');
  return row !== undefined;
}

function assertWritable(
  scope: StoredVariableScope,
  scopeId: number | null,
  key: string,
  value: JsonValue,
  isSecret: boolean,
): void {
  if (!VARIABLE_KEY_RE.test(key) || FORBIDDEN_KEYS.has(key)) {
    throw new Error(
      `Illegal variable name "${key}": expected ${VARIABLE_KEY_RE}, and not one ` +
        'of __proto__ / constructor / prototype. The regex is what stops ' +
        '`__proto__`; the explicit list is what stops the other two, which the ' +
        'regex and the database CHECK both accept.',
    );
  }
  if (isContextFactKey(key)) {
    // `storedVariableKey` refuses it at the route; this is the same rule for a
    // caller of the service (an importer, a script), at every level — the
    // instance level included, where one such row would break every render of
    // every tenant.
    throw new Error(
      `Illegal variable name "${key}": ${CONTEXT_FACT_KEYS.join(', ')} name the fact objects a ` +
        'render supplies, and a variable stored under one of them would collide with those ' +
        'facts on every render that reads it.',
    );
  }
  if (!(STORED_VARIABLE_SCOPES as readonly string[]).includes(scope)) {
    // `computed` and `bench` are not storage levels; a caller that reached
    // here with one did so around the type system.
    throw new Error(`Scope "${scope}" is not a level a variable can be stored at.`);
  }
  // 'instance', 'global' and 'tenant' carry their identity in tenant_id
  // (NULL for the instance), exactly like `settings` — a scope_id at those
  // levels would sit outside the partial unique indexes and silently allow
  // duplicate rows. Every other level (group, site, device) is scoped, and a
  // scoped row with a NULL scope_id would land in the UNSCOPED index and act
  // as a tenant-wide variable.
  const unscoped = scope === INSTANCE_SCOPE || scope === 'global' || scope === 'tenant';
  if (unscoped && scopeId !== null) {
    throw new Error(`Scope "${scope}" must have a null scope_id.`);
  }
  if (!unscoped && scopeId === null) {
    throw new Error(`Scope "${scope}" requires a scope_id.`);
  }
  if (isSecret && typeof value !== 'string') {
    throw new Error('A secret variable must be a string — the vault encrypts strings.');
  }
  if (!isSecret) {
    // A non-secret is stored in clear jsonb; prove now that it is renderable.
    assertJsonPure(value, `$.${key}`);
  }
}

// ============================================================================
// Error formatting — say WHAT, for WHICH target, and WHERE to go and fix it
// ============================================================================

function formatResolutionError(report: VariableReport): string {
  const who = targetLabel(report);
  const chain = report.chain.map((s) => s.label).join(' -> ');
  const parts: string[] = [];

  // A bench target: no device row, so its site is the narrowest level it has.
  const bench = report.deviceId === null && report.siteId !== null;
  for (const m of report.missing) {
    if (m.expectedScope === 'computed' || m.expectedScope === 'bench') {
      // Nothing an operator stores can satisfy these: say who supplies it.
      parts.push(
        `variable "${m.key}" is required by the template but was not supplied for ${who}; ` +
          (m.expectedScope === 'computed'
            ? 'it is COMPUTED by ObliWAN at render time (an allocator output), and the caller of ' +
              'this render did not hand it in — a stored value never stands in for it'
            : 'it is typed at the BENCH for one box, and the caller of this render did not hand it ' +
              'in — it is never stored') +
          (m.reason === 'secret-declared-but-absent' ? ' (it is a SECRET)' : ''),
      );
      continue;
    }
    parts.push(
      `variable "${m.key}" is required by the template but resolves to nothing for ${who}; ` +
        `it should be defined at the ${m.expectedScope} level` +
        (m.expectedScope === 'instance'
          ? ' (by a platform administrator: an instance value is shared by every tenant)'
          : '') +
        (bench && m.expectedScope === 'site'
          ? ' (the router is not enrolled yet, so its site is the narrowest level it inherits from)'
          : '') +
        (m.reason === 'secret-declared-but-absent'
          ? ' (it is a SECRET: set it in the vault, not in the template)'
          : ''),
    );
  }
  for (const t of report.typeErrors) {
    parts.push(`variable "${t.key}" (from ${t.sourceName}) ${t.message}`);
  }
  for (const r of report.rejected) {
    parts.push(`row "${r.key}" at ${r.scope}#${r.scopeId ?? '-'} was refused: ${r.reason}`);
  }

  return (
    `Refusing to render for ${who}: ${parts.join('; ')}. ` +
    `Chain searched: ${chain || '(none)'}. ` +
    'A render with an unresolved variable is not produced — an incomplete ' +
    'configuration reaching a router is what this check exists to prevent.'
  );
}
