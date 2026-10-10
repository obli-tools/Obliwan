import apiClient from './client';
import type { DeviceBrand, DeviceCapabilityFlag, DeviceFamily } from '@obliwan/shared';
import { DEVICE_BRANDS, DEVICE_FAMILIES } from '@obliwan/shared';
import { isRouteAbsent } from './change.api';
import type {
  BrandCompileResult,
  CapabilityGap,
  CompileStatus,
  CompiledArtifact,
  IntentCompileResult,
  SiteIntent,
} from '@/types/intent';
import { CAPABILITY_FLAG_LABEL_KEYS, COMPILE_STATUSES } from '@/types/intent';

/**
 * Intent Compiler.
 *
 * ── THE ROUTES — READ OFF `server/src/routes/intent.routes.ts` ──────────────
 * This module used to call `POST /intent/compile` and `/intent/saved`, which
 * the server never served. What `intent.controller.ts` answers (BARE JSON, no
 * `{ success, data }` envelope):
 *
 *   GET    /api/intent/capabilities   -> { renderable, brands: BrandCoverageRow[] }
 *   POST   /api/intent/check          { intent: SiteIntentDocument, families? }
 *   GET    /api/intent                -> SiteIntentRow[]
 *   POST   /api/intent                { intent: SiteIntentDocument, siteId? }
 *   DELETE /api/intent/:id
 *   POST   /api/intent/:id/compile    { deviceIds?, families? } -> per-target results
 *
 * ── WHAT HAS NO SERVER EQUIVALENT, AND WHY IT IS NOT FAKED ──────────────────
 * Every server route above takes or returns a `SiteIntentDocument` (shared/
 * intent.ts: `schemaVersion`, `slug`, `wan[]`, `lans[]`, `policy`,
 * `management`, `safety`, …). This editor's `SiteIntent` is a different,
 * smaller form model (`lanCidr`, one `wan`, `vlans`, `firewall`, …). Turning
 * one into the other means choosing a management policy and a safety block
 * for the customer — the anti-lockout half of the document — and a client-side
 * guess there is exactly the kind of invented behaviour this module refuses
 * to ship. So, until the editor speaks the server's schema:
 *   - `compile()` and `save()` fail with that sentence (never a 404);
 *   - `listSaved()` answers `null` ("not served"), because a stored server
 *     intent loaded into this form would be merged into the wrong shape;
 *   - `remove()` IS re-pointed (`DELETE /intent/:id`), since it is shape-free.
 *
 * ── THE ONE RULE THAT MATTERS HERE ──────────────────────────────────────────
 * A REFUSAL MUST NEVER ARRIVE EMPTY. `brandResultOf()` below refuses to
 * produce a `BrandCompileResult` that says "unsupported" with no gap attached:
 * if the server sent a status without reasons, the client synthesises a single
 * gap carrying the brand and a "the compiler did not say why" sentence. A
 * silent red cross is the exact failure the compiler exists to remove — it sends the
 * technician back to the senior, which is the cost the feature is supposed to
 * delete.
 *
 * ── The secrets rule ────────────────────────────────────────────────────────
 * `SiteIntent.wan.credentialId` is an id, never a password: this module posts
 * the intent document as-is precisely because there is nothing secret in it by
 * construction. The compiled artefact that comes back is scanned by the
 * renderer all the same — the compiler resolving a vault reference too early
 * would be a server bug, and the point of a scan is to catch server bugs.
 */

type Raw = Record<string, unknown>;

function pick(row: Raw, camel: string): unknown {
  if (camel in row) return row[camel];
  const snake = camel.replace(/[A-Z]/g, (c) => `_${c.toLowerCase()}`);
  return row[snake];
}

function n(v: unknown, fallback: number): number {
  if (v === null || v === undefined || v === '') return fallback;
  const x = typeof v === 'number' ? v : Number(v);
  return Number.isFinite(x) ? x : fallback;
}

function s(v: unknown): string | null {
  return v === null || v === undefined || v === '' ? null : String(v);
}

function asRows(payload: unknown): Raw[] {
  if (Array.isArray(payload)) return payload as Raw[];
  if (payload && typeof payload === 'object') {
    const p = payload as Raw;
    const items = p.items ?? p.rows ?? p.results ?? p.gaps ?? p.intents ?? p.saved ?? p.capabilities;
    if (Array.isArray(items)) return items as Raw[];
  }
  return [];
}

function brandOf(v: unknown): DeviceBrand | null {
  const raw = s(v);
  return raw && (DEVICE_BRANDS as readonly string[]).includes(raw) ? (raw as DeviceBrand) : null;
}

function familyOf(v: unknown): DeviceFamily | null {
  const raw = s(v);
  return raw && (DEVICE_FAMILIES as readonly string[]).includes(raw) ? (raw as DeviceFamily) : null;
}

function capabilityFlagOf(v: unknown): DeviceCapabilityFlag | null {
  const raw = s(v);
  if (!raw) return null;
  return raw in CAPABILITY_FLAG_LABEL_KEYS ? (raw as DeviceCapabilityFlag) : null;
}

/**
 * An unrecognised compile status degrades to `error`, never to `ok`.
 * A green tick this client cannot justify is how a technician ships an artefact
 * the compiler never validated.
 */
function statusOf(v: unknown): CompileStatus {
  const raw = (s(v) ?? '').toLowerCase();
  return (COMPILE_STATUSES as readonly string[]).includes(raw) ? (raw as CompileStatus) : 'error';
}

function gapOf(raw: Raw, fallbackBrand: DeviceBrand): CapabilityGap {
  return {
    brand: brandOf(pick(raw, 'brand')) ?? fallbackBrand,
    family: familyOf(pick(raw, 'family')),
    capability: capabilityFlagOf(pick(raw, 'capability') ?? pick(raw, 'flag')),
    intentPath: String(pick(raw, 'intentPath') ?? pick(raw, 'path') ?? '—'),
    detail: s(pick(raw, 'detail') ?? pick(raw, 'message') ?? pick(raw, 'reason')),
    model: s(pick(raw, 'model')),
  };
}

function artifactOf(raw: unknown, brand: DeviceBrand): CompiledArtifact | null {
  if (!raw || typeof raw !== 'object') return null;
  const row = raw as Raw;
  const body = s(pick(row, 'body') ?? pick(row, 'content') ?? pick(row, 'text'));
  if (body === null) return null;
  return {
    brand: brandOf(pick(row, 'brand')) ?? brand,
    family: familyOf(pick(row, 'family')),
    format: String(pick(row, 'format') ?? 'text'),
    body,
    opCount: n(pick(row, 'opCount') ?? pick(row, 'ops'), 0),
  };
}

export function normalizeBrandResult(raw: Raw): BrandCompileResult | null {
  const brand = brandOf(pick(raw, 'brand'));
  if (!brand) return null;
  const status = statusOf(pick(raw, 'status'));
  const gaps = asRows(pick(raw, 'gaps') ?? pick(raw, 'missing')).map((g) => gapOf(g, brand));

  // THE RULE: a refusal always carries a reason. If the compiler said "no" and
  // listed nothing, we say so explicitly rather than drawing an unexplained
  // cross — an unexplained refusal is indistinguishable, for the operator, from
  // a bug in this screen.
  if (gaps.length === 0 && (status === 'unsupported' || status === 'error' || status === 'partial')) {
    gaps.push({
      brand,
      family: familyOf(pick(raw, 'family')),
      capability: null,
      intentPath: '—',
      detail: null,     // renderer prints `intent.gapUnexplained` for this case
      model: null,
    });
  }

  return {
    brand,
    family: familyOf(pick(raw, 'family')),
    status,
    gaps,
    artifact: artifactOf(pick(raw, 'artifact') ?? pick(raw, 'artefact'), brand),
    deviceCount: n(pick(raw, 'deviceCount'), 0),
    notice: s(pick(raw, 'notice')),
  };
}

export function normalizeCompileResult(payload: unknown): IntentCompileResult {
  const row = (payload ?? {}) as Raw;
  const results = asRows(pick(row, 'results') ?? payload)
    .map(normalizeBrandResult)
    .filter((r): r is BrandCompileResult => r !== null);
  return {
    intentName: String(pick(row, 'intentName') ?? ''),
    results,
    compilerVersion: s(pick(row, 'compilerVersion')),
    compiledAt: String(pick(row, 'compiledAt') ?? new Date().toISOString()),
  };
}

// ── Capability matrix ───────────────────────────────────────────────────────

/**
 * One family's declared capabilities, as the drivers publish them.
 *
 * The screen shows this BEFORE a compile so the technician can see the shape of
 * the fleet's abilities without guessing at an intent first. `notes` is the
 * drivers' own "honest, user-visible gaps" list from `DeviceCapabilities`.
 */
export interface CapabilityMatrixRow {
  brand: DeviceBrand;
  family: DeviceFamily;
  flags: Partial<Record<DeviceCapabilityFlag, boolean>>;
  notes: string[];
  deviceCount: number;
}

function matrixRowOf(raw: Raw): CapabilityMatrixRow | null {
  const brand = brandOf(pick(raw, 'brand'));
  const family = familyOf(pick(raw, 'family'));
  if (!brand || !family) return null;
  const flagsRaw = pick(raw, 'flags') ?? pick(raw, 'capabilities') ?? raw;
  const flags: Partial<Record<DeviceCapabilityFlag, boolean>> = {};
  if (flagsRaw && typeof flagsRaw === 'object') {
    for (const [k, v] of Object.entries(flagsRaw as Raw)) {
      const flag = capabilityFlagOf(k);
      // An unknown value is FALSE. `NO_CAPABILITIES` says the safe default is
      // "we do not know how to do this", and this client mirrors it.
      if (flag) flags[flag] = v === true || v === 'true' || v === 1 || v === '1';
    }
  }
  const notes = pick(raw, 'notes');
  return {
    brand,
    family,
    flags,
    notes: Array.isArray(notes) ? notes.map((x) => String(x)) : [],
    deviceCount: n(pick(raw, 'deviceCount'), 0),
  };
}

// ── Saved intents ───────────────────────────────────────────────────────────

export interface SavedIntent {
  id: number;
  name: string;
  intent: SiteIntent;
  createdAt: string;
  createdByName: string | null;
}

/** The intent controller answers bare JSON; tolerate an envelope anyway. */
function body(payload: unknown): unknown {
  if (payload && typeof payload === 'object' && !Array.isArray(payload)) {
    const p = payload as Raw;
    if ('success' in p && 'data' in p) return p.data;
  }
  return payload;
}

/** Thrown for a feature with no server equivalent. Shaped like a server
 *  refusal so `errorMessageOf()` reads the sentence, and NOT a 404, so
 *  `isRouteAbsent()` cannot turn it into a generic "not served". */
function unsupported(message: string): Error {
  const err = new Error(message) as Error & { response: { status: number; data: { error: string } } };
  err.response = { status: 422, data: { error: message } };
  return err;
}

const SCHEMA_MISMATCH =
  'The server compiles and stores intents in the SiteIntentDocument schema (slug, WAN and LAN '
  + 'lists, policy, management, safety); this editor\'s form is not that schema, and the '
  + 'management and safety blocks cannot be guessed on the customer\'s behalf. Nothing was sent.';

// ── The client ──────────────────────────────────────────────────────────────

export const intentApi = {
  /**
   * NO SERVER EQUIVALENT for this document — see the header. The server's
   * compile is `POST /intent/:id/compile` on a STORED `SiteIntentDocument`
   * (and `POST /intent/check` on an unsaved one), neither of which accepts this
   * form's `SiteIntent`. Fails with that sentence rather than a 404.
   */
  async compile(_intent: SiteIntent, _brands?: DeviceBrand[]): Promise<IntentCompileResult | null> {
    throw unsupported(SCHEMA_MISMATCH);
  },

  /** `GET /intent/capabilities` → `{ renderable, brands }`; one row per family. */
  async capabilities(): Promise<CapabilityMatrixRow[] | null> {
    try {
      const res = await apiClient.get<unknown>('/intent/capabilities');
      const payload = body(res.data);
      const rows = payload && typeof payload === 'object' && !Array.isArray(payload)
        ? asRows((payload as Raw).brands ?? payload)
        : asRows(payload);
      return rows
        .map(matrixRowOf)
        .filter((r): r is CapabilityMatrixRow => r !== null);
    } catch (err) {
      if (isRouteAbsent(err)) return null;
      throw err;
    }
  },

  /**
   * `null` = "not served", on purpose and without a request. `GET /intent`
   * exists, but every row it returns is a `SiteIntentDocument`, and the page
   * merges a saved row straight into this form's state — a different shape.
   */
  async listSaved(): Promise<SavedIntent[] | null> {
    return null;
  },

  /** NO SERVER EQUIVALENT for this document — see `compile()`. */
  async save(_name: string, _intent: SiteIntent): Promise<SavedIntent | null> {
    throw unsupported(SCHEMA_MISMATCH);
  },

  /** `DELETE /intent/:id` (204). Shape-free, so it is the one re-pointed call. */
  async remove(id: number): Promise<boolean> {
    try {
      await apiClient.delete(`/intent/${id}`);
      return true;
    } catch (err) {
      if (isRouteAbsent(err)) return false;
      throw err;
    }
  },
};
