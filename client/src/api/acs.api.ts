import apiClient from './client';
import type { ApiResponse, DeviceBrand, DeviceFamily } from '@obliwan/shared';
import { DEVICE_BRANDS, DEVICE_FAMILIES } from '@obliwan/shared';
import { isRouteAbsent } from './change.api';
import type {
  CwmpCpe,
  CwmpDataModel,
  CwmpFile,
  CwmpParameter,
  CwmpReachability,
  CwmpRpcDirection,
  CwmpRpcEntry,
  CwmpRpcLogView,
  CwmpTask,
  CwmpTaskCommand,
  CwmpTaskState,
  EnqueueTaskRequest,
} from '@/types/acs';
import {
  CWMP_CAPABLE_FAMILIES,
  CWMP_DATA_MODELS,
  CWMP_REACHABILITIES,
  CWMP_RPC_DIRECTIONS,
  CWMP_TASK_COMMANDS,
  CWMP_TASK_STATES,
  isSecretParameterPath,
} from '@/types/acs';

/**
 * ACS / TR-069.
 *
 * ── THE ROUTES — READ OFF `server/src/routes/acs.routes.ts` ─────────────────
 * This module used to call a `/acs/cpe…`, `/acs/tasks`, `/acs/firmware`
 * surface that was written down before the server existed and that the server
 * never served, so every call was a 404 rendered as "not served by this
 * build". It now calls what `acs.controller.ts` actually answers:
 *
 *   GET    /api/acs/devices                                 -> AcsDeviceSummary[]
 *   GET    /api/acs/devices/:deviceId                       -> AcsDeviceDetail (+ meta)
 *   GET    /api/acs/devices/:deviceId/parameters?prefix&limit -> CwmpParameter[]
 *   GET    /api/acs/devices/:deviceId/tasks                 -> AcsTaskSummary[]
 *   DELETE /api/acs/devices/:deviceId/tasks/:taskId
 *   POST   /api/acs/devices/:deviceId/tasks/:taskId/requeue { changeJobId, confirm } -> 202 task
 *   POST   /api/acs/devices/:deviceId/read     { paths }               -> 202 task
 *   POST   /api/acs/devices/:deviceId/discover                         -> 202 task
 *   POST   /api/acs/devices/:deviceId/write    { ops, changeJobId }    -> 202 task
 *   POST   /api/acs/devices/:deviceId/download { fileId, changeJobId } -> 202 task
 *   POST   /api/acs/devices/:deviceId/reboot   { changeJobId }         -> 202 task
 *   POST   /api/acs/devices/:deviceId/refresh                          -> CwmpRefreshOutcome
 *   GET    /api/acs/devices/:deviceId/rpc-log  -> entries[], `meta.enabled`
 *   GET    /api/acs/files                      -> CwmpFileRecord[]
 *
 * What the old surface promised and the server has NO equivalent for fails
 * HERE, with a sentence, and never reaches the wire as a 404:
 *   - `AddObject` / `DeleteObject`: the server's task kinds are GPV, SPV,
 *     Download and Reboot (`CWMP_TASK_KINDS`), and nothing else can be queued.
 *   - Removing a firmware file: `/acs/files` is read-only.
 *   - `search` / `family` / `reachability` on the list: the server returns the
 *     tenant's whole enrolled fleet, so those filters run here.
 * `GetParameterNames` is mapped onto `/discover` on purpose: the ACS has
 * no GPN, and the server's documented substitute is ONE GetParameterValues on
 * the root partial path, which returns the names AND the values.
 *
 * Writes (SPV, Download, Reboot) need a change job. Without a
 * `changeJobId` the server answers 409 with the sentence naming the door, and
 * that sentence is thrown to the caller untouched — never swallowed here.
 *
 * "Connection Request" is `/refresh`, which never dials the CPE
 * (`connectionRequestSupported: false` on every device): it lowers the inform
 * interval and says when the box will call in. It is therefore ALWAYS mapped
 * to `delivered: false`, with the server's explanation as the reason.
 *
 * ── THE SECRETS RULE IS THE WHOLE POINT OF THE NORMALISERS BELOW ────────────
 * The last audit found the L2TP passwords of an entire fleet in a jsonb column
 * served to the UI. The TR-069 data model is the richest possible source of
 * exactly that mistake: `...WANPPPConnection.1.Password` is a first-class leaf
 * of the standard. So `parameterOf()` REDACTS on the way in — before the value
 * ever reaches a component — whenever the path looks like a secret, whatever
 * the server chose to send. Over-redaction shows up as a visible chip the
 * operator can report; under-redaction shows up in a screenshot in a ticket.
 *
 * The same rule kills the value echo in `taskOf()`: an enqueued
 * SetParameterValues is summarised by its PATHS and never by its values — and
 * that matters more now, because the 202 of `/write` echoes the whole payload.
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

function nOrNull(v: unknown): number | null {
  if (v === null || v === undefined || v === '') return null;
  const x = typeof v === 'number' ? v : Number(v);
  return Number.isFinite(x) ? x : null;
}

function s(v: unknown): string | null {
  return v === null || v === undefined || v === '' ? null : String(v);
}

function bool(v: unknown, fallback = false): boolean {
  if (v === null || v === undefined) return fallback;
  if (typeof v === 'boolean') return v;
  return v === 'true' || v === 't' || v === 1 || v === '1';
}

/** Tri-state: `null` really means "not stated", never "false". */
function boolOrNull(v: unknown): boolean | null {
  if (v === null || v === undefined || v === '') return null;
  if (typeof v === 'boolean') return v;
  if (v === 'true' || v === 't' || v === 1 || v === '1') return true;
  if (v === 'false' || v === 'f' || v === 0 || v === '0') return false;
  return null;
}

function asRows(payload: unknown): Raw[] {
  if (Array.isArray(payload)) return payload as Raw[];
  if (payload && typeof payload === 'object') {
    const p = payload as Raw;
    const items = p.items ?? p.rows ?? p.cpe ?? p.cpes ?? p.devices ?? p.tasks
      ?? p.parameters ?? p.entries ?? p.files ?? p.firmware;
    if (Array.isArray(items)) return items as Raw[];
  }
  return [];
}

function strList(v: unknown): string[] {
  if (Array.isArray(v)) return v.map((x) => String(x)).filter((x) => x.length > 0);
  if (typeof v === 'string' && v.length > 0) return v.split(',').map((x) => x.trim()).filter(Boolean);
  // `vendorQuirks` is an object of OBSERVED flags (`{ noCookie: true }`): only
  // the keys that are actually set are quirks.
  if (v && typeof v === 'object') {
    return Object.entries(v as Raw).filter(([, flag]) => flag !== false && flag !== null).map(([k]) => k);
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

function familyList(v: unknown): DeviceFamily[] {
  return strList(v).filter((x): x is DeviceFamily => (DEVICE_FAMILIES as readonly string[]).includes(x));
}

/** Thrown for a feature the server has no route for. The message IS the UI
 *  text: `errorMessageOf()` reads `response.data.error`, so it is shaped the
 *  same way an AppError from the server would be. */
function unsupported(message: string): Error {
  const err = new Error(message) as Error & { response: { status: number; data: { error: string } } };
  // 422 and not 404: `isRouteAbsent()` must NOT turn this into "this build
  // does not serve the ACS", which would hide the sentence behind a generic one.
  err.response = { status: 422, data: { error: message } };
  return err;
}

// ── Normalisers ─────────────────────────────────────────────────────────────

/**
 * The server classifies on four values (`never_seen | online | stale | lost`,
 * `classifyReachability()` in shared/cwmp.ts); this screen speaks five. `stale`
 * (past 1.5 intervals) and `lost` (past 4) are both "the next Inform is late"
 * — `overdue` — and neither is ever folded into `online`.
 *
 * An unrecognised reachability degrades to `unknown`, never to `online`.
 * "We do not know whether this CPE is talking to us" is a fact an operator can
 * act on; a green dot he cannot trust is worse than no dot.
 */
function reachabilityOf(v: unknown): CwmpReachability {
  const raw = (s(v) ?? '').toLowerCase();
  if (raw === 'never_seen') return 'never_informed';
  if (raw === 'stale' || raw === 'lost') return 'overdue';
  return (CWMP_REACHABILITIES as readonly string[]).includes(raw)
    ? (raw as CwmpReachability)
    : 'unknown';
}

function dataModelOf(v: unknown): CwmpDataModel | null {
  const raw = (s(v) ?? '').toLowerCase().replace(/[^a-z0-9]/g, '');
  return (CWMP_DATA_MODELS as readonly string[]).includes(raw) ? (raw as CwmpDataModel) : null;
}

/**
 * `AcsDeviceSummary` / `AcsDeviceDetail`, plus the detail's `meta` (which is
 * where the Connection Request URL lives — on the envelope, not on the row).
 */
export function normalizeCpe(raw: Raw, meta: Raw = {}): CwmpCpe {
  const events = pick(raw, 'lastInformEvents');
  return {
    deviceId: n(pick(raw, 'deviceId') ?? pick(raw, 'id'), 0),
    deviceName: s(pick(raw, 'deviceName') ?? pick(raw, 'name')),
    siteId: nOrNull(pick(raw, 'siteId')),
    siteName: s(pick(raw, 'siteName')),
    brand: brandOf(pick(raw, 'brand')),
    family: familyOf(pick(raw, 'family')),
    model: s(pick(raw, 'model')),
    cwmpId: String(pick(raw, 'cwmpId') ?? pick(raw, 'cwmp_id') ?? ''),
    dataModel: dataModelOf(pick(raw, 'dataModel')),
    rootPrefix: s(pick(raw, 'rootPrefix')),
    cwmpVersion: s(pick(raw, 'cwmpVersion')),
    softwareVersion: s(pick(raw, 'softwareVersion') ?? pick(raw, 'osVersion')),
    periodicInformInterval: nOrNull(pick(raw, 'periodicInformInterval')),
    lastInformAt: s(pick(raw, 'lastInformAt')),
    lastInformEvent: s(pick(raw, 'lastInformEvent'))
      ?? (Array.isArray(events) && events.length > 0 ? String(events[0]) : null),
    reachability: reachabilityOf(pick(raw, 'reachability')),
    // A Connection Request URL that is present but empty is NOT a usable one.
    hasConnectionRequest:
      bool(pick(raw, 'hasConnectionRequest'))
      || (s(pick(raw, 'connectionRequestUrl') ?? pick(meta, 'connectionRequestUrl')) !== null),
    // The server never attempts one (`connectionRequestSupported: false`), so
    // "never attempted" is the only true answer.
    connectionRequestOk: boolOrNull(pick(raw, 'connectionRequestOk')),
    lastConnectionRequestAt: s(pick(raw, 'lastConnectionRequestAt')),
    queuedTasks: n(pick(raw, 'queuedTasks') ?? pick(raw, 'pendingTasks'), 0),
    parameterCount: n(pick(raw, 'parameterCount'), 0),
    vendorQuirks: strList(pick(raw, 'vendorQuirks')),
  };
}

/**
 * The secrets rule enforcement point. A parameter whose PATH looks like a secret is
 * redacted here, on the way in, whether or not the server flagged it — the
 * component layer never sees the string at all.
 */
export function normalizeParameter(raw: Raw): CwmpParameter {
  const path = String(pick(raw, 'path') ?? pick(raw, 'name') ?? '');
  // The server spells its flag `isSecret`; `redacted` is kept for older rows.
  const serverRedacted = bool(pick(raw, 'redacted')) || bool(pick(raw, 'isSecret'));
  const secretPath = isSecretParameterPath(path);
  const rawValue = pick(raw, 'value');
  return {
    path,
    value: serverRedacted || secretPath ? null : s(rawValue),
    valueType: s(pick(raw, 'valueType') ?? pick(raw, 'type')),
    writable: bool(pick(raw, 'writable')),
    notification: nOrNull(pick(raw, 'notification')),
    redacted: serverRedacted || secretPath,
    updatedAt: s(pick(raw, 'updatedAt')),
  };
}

/** The server's task `kind` → the RPC name this screen shows. */
const KIND_TO_COMMAND: Record<string, CwmpTaskCommand> = {
  get_parameter_values: 'GetParameterValues',
  set_parameter_values: 'SetParameterValues',
  download: 'Download',
  reboot: 'Reboot',
};

function taskCommandOf(v: unknown): CwmpTaskCommand {
  const raw = s(v) ?? '';
  const mapped = KIND_TO_COMMAND[raw.toLowerCase()];
  if (mapped) return mapped;
  const hit = CWMP_TASK_COMMANDS.find((c) => c.toLowerCase() === raw.toLowerCase());
  // An unknown RPC name is shown verbatim rather than mapped onto a known one:
  // rendering an unrecognised command as `Reboot` would be catastrophic.
  return hit ?? (raw as CwmpTaskCommand);
}

/**
 * An unknown task state degrades to `queued` — the state that claims the LEAST.
 * Reading an unrecognised value as `done` would tell an operator a firmware
 * push landed when nobody knows whether it did.
 */
function taskStateOf(v: unknown): CwmpTaskState {
  const raw = (s(v) ?? '').toLowerCase();
  return (CWMP_TASK_STATES as readonly string[]).includes(raw) ? (raw as CwmpTaskState) : 'queued';
}

/**
 * Two server shapes land here: `AcsTaskSummary` from the list (with an already
 * redacted `payloadSummary`) and the raw `CwmpTask` echoed by a 202 (with the
 * full `payload` — SPV values included). The second one is summarised from
 * PATHS only; `op.value` is never read.
 */
export function normalizeTask(raw: Raw): CwmpTask {
  const explicit = s(pick(raw, 'summary') ?? pick(raw, 'payloadSummary'));
  const payload = (pick(raw, 'payload') ?? {}) as Raw;
  const ops = Array.isArray(payload.ops) ? (payload.ops as Raw[]) : [];
  const paths = strList(pick(raw, 'paths')).length > 0
    ? strList(pick(raw, 'paths'))
    : strList(payload.paths).length > 0
      ? strList(payload.paths)
      : ops.map((op) => String(op.path ?? '')).filter(Boolean);
  const values = pick(raw, 'values');
  const derived = paths.length > 0
    ? paths.join(', ')
    : values && typeof values === 'object'
      ? Object.keys(values as Raw).join(', ')
      : null;
  const fault = (pick(raw, 'fault') ?? null) as Raw | null;
  return {
    id: n(pick(raw, 'id'), 0),
    deviceId: n(pick(raw, 'deviceId'), 0),
    deviceName: s(pick(raw, 'deviceName')),
    command: taskCommandOf(pick(raw, 'command') ?? pick(raw, 'kind') ?? pick(raw, 'rpc')),
    commandKey: String(pick(raw, 'commandKey') ?? pick(raw, 'command_key') ?? ''),
    state: taskStateOf(pick(raw, 'state') ?? pick(raw, 'status')),
    attempts: n(pick(raw, 'attempts'), 0),
    summary: explicit ?? derived,
    // `CwmpFault.code` is the CWMP code (9001…); `faultCode` there is the SOAP
    // one (`Client`), which is the less useful of the two to an operator.
    faultCode: s(pick(raw, 'faultCode') ?? (fault ? fault.code ?? fault.faultCode : null)),
    faultString: s(pick(raw, 'faultString') ?? (fault ? fault.faultString : null)),
    createdAt: String(pick(raw, 'createdAt') ?? ''),
    sentAt: s(pick(raw, 'sentAt')),
    completedAt: s(pick(raw, 'completedAt')),
    expiresAt: s(pick(raw, 'expiresAt')),
    createdByName: s(pick(raw, 'createdByName')),
    changeJobId: idOrNull(pick(raw, 'changeJobId')),
    requeuedFromTaskId: idOrNull(pick(raw, 'requeuedFromTaskId')),
  };
}

/** A positive integer id, or null — never a `0` standing for "absent". */
function idOrNull(v: unknown): number | null {
  const id = typeof v === 'number' ? v : typeof v === 'string' && v.trim() !== '' ? Number(v) : NaN;
  return Number.isInteger(id) && id > 0 ? id : null;
}

function directionOf(v: unknown): CwmpRpcDirection {
  const raw = (s(v) ?? '').toLowerCase();
  if ((CWMP_RPC_DIRECTIONS as readonly string[]).includes(raw)) return raw as CwmpRpcDirection;
  // `inbound` / `outbound` / `in` / `out` all appear in CWMP tooling.
  if (raw.startsWith('in') || raw === 'cpe' || raw === 'request') return 'cpe_to_acs';
  return 'acs_to_cpe';
}

/** `readRpcLog()` answers `{ ts, direction, method, cwmpId, httpStatus,
 *  byteCount, body }` and carries no device id — it is passed in. */
export function normalizeRpcEntry(raw: Raw, deviceId = 0): CwmpRpcEntry {
  const at = String(pick(raw, 'at') ?? pick(raw, 'ts') ?? pick(raw, 'createdAt') ?? '');
  const rpc = String(pick(raw, 'rpc') ?? pick(raw, 'method') ?? '—');
  return {
    id: String(pick(raw, 'id') ?? `${at}-${pick(raw, 'direction')}-${rpc}`),
    deviceId: n(pick(raw, 'deviceId'), deviceId),
    sessionId: s(pick(raw, 'sessionId')),
    at,
    direction: directionOf(pick(raw, 'direction')),
    rpc,
    httpStatus: nOrNull(pick(raw, 'httpStatus')),
    faultCode: s(pick(raw, 'faultCode')),
    bodyExcerpt: s(pick(raw, 'bodyExcerpt') ?? pick(raw, 'body')),
  };
}

/** Brand → the families the ACS manages for it (`ACS_BRAND_COVERAGE`). */
const BRAND_FAMILIES: Record<string, DeviceFamily[]> = {
  draytek: ['draytek_vigor'],
  zyxel: ['zyxel_cpe'],
};

/**
 * `CwmpFileRecord` declares a `brand` and a `modelPattern`, not a family list.
 * A file with a brand is offered to that brand's CWMP family only. A file with
 * NO brand is one the server itself accepts for any device
 * (`assertFileFitsDevice()`: "may be a vendor config file, which is
 * model-agnostic"), so it is offered to both CWMP families — and the server
 * re-checks brand and model before the task exists, which is the guard that
 * counts.
 */
export function normalizeFile(raw: Raw): CwmpFile {
  const declared = familyList(pick(raw, 'families'));
  const brand = s(pick(raw, 'brand'));
  const families = declared.length > 0
    ? declared
    : brand
      ? BRAND_FAMILIES[brand.toLowerCase()] ?? []
      : [...CWMP_CAPABLE_FAMILIES];
  return {
    id: n(pick(raw, 'id'), 0),
    name: String(pick(raw, 'name') ?? pick(raw, 'filename') ?? ''),
    fileType: String(pick(raw, 'fileType') ?? '1 Firmware Upgrade Image'),
    version: s(pick(raw, 'version')),
    sizeBytes: nOrNull(pick(raw, 'sizeBytes') ?? pick(raw, 'size')),
    sha256: s(pick(raw, 'sha256')),
    families,
    uploadedAt: String(pick(raw, 'uploadedAt') ?? pick(raw, 'createdAt') ?? ''),
    uploadedByName: s(pick(raw, 'uploadedByName')),
  };
}

/** Outcome of a Connection Request attempt — see the header of `types/acs.ts`
 *  for why this is never presented as "refreshed". */
export interface ConnectionRequestOutcome {
  /** The ACS reached the CPE's CR endpoint and it answered 200. */
  delivered: boolean;
  /** Why it did not, in the server's words. Redacted, shown verbatim. */
  reason: string | null;
  /** Always true when the request could not be delivered: the task stays in
   *  the queue and will run at the next Inform. */
  queued: boolean;
}

/**
 * `CwmpRefreshOutcome` → the outcome this screen renders. `supported` is
 * ALWAYS false server-side, so `delivered` is always false and the reason is
 * the server's own `explanation` (with the ETA appended when it has one).
 */
function outcomeOf(payload: unknown): ConnectionRequestOutcome {
  const row = (payload ?? {}) as Raw;
  const explanation = s(pick(row, 'explanation') ?? pick(row, 'reason') ?? pick(row, 'error'));
  const eta = nOrNull(pick(row, 'etaSeconds'));
  return {
    delivered: bool(pick(row, 'delivered')),
    reason: explanation && eta !== null ? `${explanation} (~${Math.round(eta)} s)` : explanation,
    // Fail-safe default: if the server did not say, assume the work is still
    // pending rather than telling the operator it was dropped.
    queued: boolOrNull(pick(row, 'queued')) ?? true,
  };
}

/** Exactly one of `value` / `secretRef` per op (server's Zod refine). */
interface WriteOp {
  path: string;
  value: string;
  valueType?: string;
}

// ── The client ──────────────────────────────────────────────────────────────

export const acsApi = {
  /**
   * `null` = this build does not serve the ACS API. Not "no CPE".
   * The server has no filter parameters: it returns the tenant's enrolled
   * fleet, and `search` / `family` / `reachability` / `limit` apply here.
   */
  async listCpe(params: {
    search?: string;
    family?: DeviceFamily | '';
    reachability?: CwmpReachability | '';
    limit?: number;
  } = {}): Promise<CwmpCpe[] | null> {
    try {
      const res = await apiClient.get<ApiResponse<unknown>>('/acs/devices');
      const needle = (params.search ?? '').trim().toLowerCase();
      return asRows(res.data.data)
        .map((row) => normalizeCpe(row))
        .filter((c) => !params.family || c.family === params.family)
        .filter((c) => !params.reachability || c.reachability === params.reachability)
        .filter((c) => !needle
          || [c.deviceName, c.cwmpId, c.model, c.softwareVersion]
            .some((f) => (f ?? '').toLowerCase().includes(needle)))
        .slice(0, params.limit ?? 200);
    } catch (err) {
      if (isRouteAbsent(err)) return null;
      throw err;
    }
  },

  /**
   * `null` = no ACS API in this build. `'not_enrolled'` = the route answered
   * and this device is not enrolled — the server's 404 for an existing device,
   * which the device tab renders as its own state, not as an outage.
   */
  async getCpe(deviceId: number): Promise<CwmpCpe | 'not_enrolled' | null> {
    try {
      const res = await apiClient.get<ApiResponse<unknown> & { meta?: Raw }>(`/acs/devices/${deviceId}`);
      const payload = res.data.data;
      if (!payload || typeof payload !== 'object') return 'not_enrolled';
      return normalizeCpe(payload as Raw, res.data.meta ?? {});
    } catch (err) {
      const st = (err as { response?: { status?: number } }).response?.status;
      if (st === 404) return 'not_enrolled';
      if (isRouteAbsent(err)) return null;
      throw err;
    }
  },

  /** `search` has no server parameter; it filters the returned page here. */
  async listParameters(
    deviceId: number,
    opts: { prefix?: string; search?: string; limit?: number } = {},
  ): Promise<CwmpParameter[] | null> {
    try {
      const res = await apiClient.get<ApiResponse<unknown>>(`/acs/devices/${deviceId}/parameters`, {
        params: {
          prefix: opts.prefix || undefined,
          limit: opts.limit ?? 2000,
        },
      });
      const needle = (opts.search ?? '').trim().toLowerCase();
      const rows = asRows(res.data.data).map(normalizeParameter);
      return needle ? rows.filter((p) => p.path.toLowerCase().includes(needle)) : rows;
    } catch (err) {
      if (isRouteAbsent(err)) return null;
      throw err;
    }
  },

  /** The server caps the list at 200; `limit` trims it further here. */
  async listTasks(deviceId: number, limit = 100): Promise<CwmpTask[] | null> {
    try {
      const res = await apiClient.get<ApiResponse<unknown>>(`/acs/devices/${deviceId}/tasks`);
      return asRows(res.data.data).map(normalizeTask).slice(0, limit);
    } catch (err) {
      if (isRouteAbsent(err)) return null;
      throw err;
    }
  },

  /**
   * Enqueue an RPC. It does NOT run now — it runs when the CPE next opens a
   * session. Every caller of this is responsible for saying so on screen.
   *
   * One server route per kind. SPV / Download / Reboot need `changeJobId`
   * (change-queue rule); without it the server's 409 is thrown as-is so its sentence reaches
   * the operator. `valueTypes` carries each SPV leaf's `xsi:type` — a missing
   * or wrong one makes the CPE reject the WHOLE envelope, and the server's
   * default is `xsd:string`.
   */
  async enqueue(
    req: EnqueueTaskRequest & { changeJobId?: number; valueTypes?: Record<string, string | null> },
  ): Promise<CwmpTask | null> {
    const base = `/acs/devices/${req.deviceId}`;
    const paths = (req.paths ?? []).filter((p) => p.trim().length > 0);
    let url: string;
    let body: Raw;
    switch (req.command) {
      case 'GetParameterValues':
        // No usable path = the whole tree, which is exactly what `/discover`
        // queues (one GPV on the root prefix the server knows for this CPE).
        if (paths.length === 0) { url = `${base}/discover`; body = {}; }
        else { url = `${base}/read`; body = { paths }; }
        break;
      case 'GetParameterNames':
        // No GPN. `/discover` is the server's substitute and pulls the
        // subtree by name AND value. A GPN aimed below the root has no
        // equivalent, and saying so beats silently reading something else.
        if (paths.length > 1) {
          throw unsupported('GetParameterNames is not supported by the ACS (no GPN). Use GetParameterValues on the path instead.');
        }
        url = `${base}/discover`;
        body = {};
        break;
      case 'SetParameterValues': {
        const ops: WriteOp[] = Object.entries(req.values ?? {}).map(([path, value]) => {
          const valueType = req.valueTypes?.[path];
          return valueType ? { path, value, valueType } : { path, value };
        });
        url = `${base}/write`;
        body = { ops, changeJobId: req.changeJobId };
        break;
      }
      case 'Download':
        url = `${base}/download`;
        body = { fileId: req.fileId, changeJobId: req.changeJobId };
        break;
      case 'Reboot':
        url = `${base}/reboot`;
        body = { changeJobId: req.changeJobId };
        break;
      default:
        throw unsupported(
          `${req.command} is not supported by the ACS: it queues GetParameterValues, SetParameterValues, Download and Reboot only.`,
        );
    }
    try {
      const res = await apiClient.post<ApiResponse<unknown>>(url, body);
      const payload = res.data.data;
      if (!payload || typeof payload !== 'object') return null;
      return normalizeTask(payload as Raw);
    } catch (err) {
      // A 404 here is "device not found / not enrolled" with a sentence, not a
      // missing route: the route table above is the server's own.
      if ((err as { response?: { status?: number } }).response?.status === 501) return null;
      throw err;
    }
  },

  /**
   * Re-send a write whose outcome is `unknown`, as a NEW task. The server never
   * does it on its own; this is the explicit door, and it demands a live
   * change job of the same device plus `confirm: true` (the operator says the
   * device was checked). A refusal (400/404/409) is thrown so its sentence
   * reaches the operator.
   */
  async requeueTask(deviceId: number, taskId: number, changeJobId: number): Promise<CwmpTask | null> {
    try {
      const res = await apiClient.post<ApiResponse<unknown>>(
        `/acs/devices/${deviceId}/tasks/${taskId}/requeue`,
        { changeJobId, confirm: true },
      );
      const payload = res.data.data;
      if (!payload || typeof payload !== 'object') return null;
      return normalizeTask(payload as Raw);
    } catch (err) {
      if ((err as { response?: { status?: number } }).response?.status === 501) return null;
      throw err;
    }
  },

  /** The server scopes the cancel by device: `DELETE …/devices/:id/tasks/:taskId`. */
  async cancelTask(deviceId: number, taskId: number): Promise<boolean> {
    try {
      await apiClient.delete<ApiResponse<unknown>>(`/acs/devices/${deviceId}/tasks/${taskId}`);
      return true;
    } catch (err) {
      // 404 = "Task not found, or already finished" — a sentence, thrown.
      if ((err as { response?: { status?: number } }).response?.status === 501) return false;
      throw err;
    }
  },

  /**
   * Ask the ACS to bring the CPE in sooner.
   *
   * Server-side this is `/refresh`, which never pokes the CPE: it lowers the
   * periodic inform interval and answers when the box should next call in. So
   * `delivered` is always false and the reason is the server's explanation.
   * `null` = no ACS API in this build.
   */
  async connectionRequest(deviceId: number): Promise<ConnectionRequestOutcome | null> {
    try {
      const res = await apiClient.post<ApiResponse<unknown>>(`/acs/devices/${deviceId}/refresh`, {});
      return outcomeOf(res.data.data);
    } catch (err) {
      if (isRouteAbsent(err)) return null;
      // A refused refresh is an ANSWER, not an outage: the queued work still
      // runs at the next Inform.
      const data = (err as { response?: { data?: { error?: string; message?: string } } }).response?.data;
      return { delivered: false, reason: data?.error ?? data?.message ?? null, queued: true };
    }
  },

  /**
   * The RPC log. `enabled:false` is a first-class answer — the design disables
   * capture by default, and an empty list means two opposite things depending
   * on that flag. The server puts the flag in `meta`, the entries in `data`,
   * and caps the page at 200; `limit` trims it further here.
   */
  async rpcLog(deviceId: number, limit = 200): Promise<CwmpRpcLogView | null> {
    try {
      const res = await apiClient.get<ApiResponse<unknown> & { meta?: Raw }>(
        `/acs/devices/${deviceId}/rpc-log`,
      );
      const payload = res.data.data;
      const meta = res.data.meta ?? {};
      const row = (payload && !Array.isArray(payload) ? payload : {}) as Raw;
      return {
        // Absent flag = capture is OFF. The design says disabled by default, and
        // guessing "on" would make an empty log look like a dead CPE.
        enabled: bool(pick(meta, 'enabled') ?? pick(row, 'enabled'), false),
        retentionDays: nOrNull(pick(meta, 'retentionDays') ?? pick(row, 'retentionDays')),
        entries: asRows(pick(row, 'entries') ?? payload)
          .map((e) => normalizeRpcEntry(e, deviceId))
          .slice(0, limit),
      };
    } catch (err) {
      if (isRouteAbsent(err)) return null;
      throw err;
    }
  },

  /** Files available for Download (`GET /acs/files`): firmware and config. */
  async listFirmware(): Promise<CwmpFile[] | null> {
    try {
      const res = await apiClient.get<ApiResponse<unknown>>('/acs/files');
      return asRows(res.data.data).map(normalizeFile);
    } catch (err) {
      if (isRouteAbsent(err)) return null;
      throw err;
    }
  },

  /**
   * NO SERVER EQUIVALENT. `/acs/files` is read-only: there is no upload and no
   * delete route. Answers `false` without a request, which the page renders
   * as "the firmware route is not served by this build" — true, and better
   * than a 404 that looks like a transient failure.
   */
  async removeFirmware(_id: number): Promise<boolean> {
    return false;
  },

};
