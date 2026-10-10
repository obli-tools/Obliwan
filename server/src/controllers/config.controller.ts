/**
 * Config snapshots / NCM — HTTP layer.
 *
 * The three rules of `snmp.controller.ts` apply verbatim, and the third one is
 * sharper here:
 *
 *  1. THE TENANT IS ALWAYS `req.tenantId`, from the session. Every service call
 *     takes it as its first argument and every one of them joins `devices` on
 *     it, because `config_snapshots` and the ten `ncm_*` tables have no tenant
 *     column of their own.
 *
 *  2. A CROSS-TENANT ID IS A 404, NOT A 403.
 *
 *  3. WHAT THIS ENDPOINT SERVES IS A CONFIGURATION. `CONFIG_READ` is
 *     deliberately distinct from `DEVICE_READ`: seeing that a device
 *     exists is a different question from seeing what it carries. `raw_gz` is
 *     the REDACTED export — `show-sensitive=no` is hard-wired in
 *     `collect.service.ts` and a non-empty secret prop aborts the collection
 *     outright — which is why it is served under `CONFIG_READ` and not
 *     `SECRET_READ`.
 */

import type { NextFunction, Request, Response } from 'express';
import { z } from 'zod';
import { NcmVersionAheadError } from '@obliwan/shared';
import { AppError } from '../middleware/errorHandler';
import * as snapshots from '../services/config/snapshot.service';
import { collectAndStore, hasNormalizer, NoNormalizerError, SensitiveMaterialError } from '../services/config/collect.service';
import { reindexSnapshot } from '../services/config/ncmIndex.service';
import { getDevice } from '../services/fleet/device.service';
import { DriverError } from '../services/drivers/types';
import { BindingAssertionError } from '../services/fleet/deviceBinding.service';
import { godViewMeta, hasGlobalView, requirePickedTenant } from '../utils/globalView';
import { startTenantCollect, tenantCollectState } from '../services/drift/runtime';
import { deviceListScope } from '../services/teamScope.service';

function parseId(raw: string, what = 'id'): number {
  const id = Number.parseInt(raw, 10);
  if (!Number.isInteger(id) || id <= 0) throw new AppError(400, `Invalid ${what}`);
  return id;
}

/** Snapshot ids are bigint: they arrive as strings and must stay strings, or a
 *  fleet past 2^53 snapshots starts serving the wrong row. */
function parseBigId(raw: string, what = 'id'): string {
  if (!/^[0-9]{1,19}$/.test(raw)) throw new AppError(400, `Invalid ${what}`);
  return raw;
}

function parse<T>(schema: z.ZodType<T>, value: unknown): T {
  const result = schema.safeParse(value);
  if (!result.success) {
    const flat = result.error.flatten();
    const fields = Object.entries(flat.fieldErrors)
      .map(([f, m]) => `${f}: ${((m as string[] | undefined) ?? []).join(', ')}`)
      .concat(flat.formErrors)
      .filter((s) => s.length > 0)
      .join('; ');
    throw new AppError(400, fields ? `Validation failed — ${fields}` : 'Validation failed');
  }
  return result.data;
}

const listQuery = z.object({
  limit: z.coerce.number().int().min(1).max(200).optional(),
  offset: z.coerce.number().int().min(0).optional(),
});

/**
 * ┌─ WHY THIS CONTROLLER MAPS `DriverError` ITSELF ────────────────────────────┐
 * │ `errorHandler` knows two things: `AppError`, and a PostgreSQL error. A     │
 * │ `DriverError` is neither — and because it carries a `code` STRING it is    │
 * │ even mistaken for a pg error on the way through, falls out of the switch   │
 * │ and reaches the caller as a bare `500 Internal server error`. The one      │
 * │ thing the operator needs is then gone: WHY the box could not be read.      │
 * │                                                                           │
 * │ A "Collect now" button that answers "Internal server error" to a device    │
 * │ with no SSH transport, to a family with no collector and to a tunnel that  │
 * │ is down alike teaches nothing and sends every one of them to the wrong     │
 * │ person. So the acquisition taxonomy is mapped once, here, where the only   │
 * │ route that dials a device on demand lives.                                 │
 * │                                                                           │
 * │ NOTHING IN THE 4xx BAND. 401 and 403 are the SESSION's answers — the       │
 * │ client's interceptor logs the operator out on a 401 — and a credential the │
 * │ VAULT holds being refused by a customer's router has nothing to do with    │
 * │ the operator's own session. Those are 502: for the fleet, we are the       │
 * │ gateway.                                                                   │
 * │                                                                           │
 * │ The messages are forwarded verbatim, and that is checked rather than       │
 * │ assumed: every message on this path names a device id, a family, a         │
 * │ transport kind, an exit code or a prop NAME, and never a credential nor a  │
 * │ configuration value.                                                      │
 * │                                                                           │
 * │ `UNKNOWN` is deliberately absent. It means the layer below could not       │
 * │ classify its own failure, so this layer will not classify it either: it    │
 * │ falls through to the 500 and the full error to the server log.             │
 * └───────────────────────────────────────────────────────────────────────────┘
 */
const DRIVER_ERROR_STATUS: Readonly<Record<string, number>> = {
  NOT_IMPLEMENTED: 501,
  UNSUPPORTED: 501,
  // The fleet's configuration is wrong, not the request: a channel is missing,
  // or another session holds the box. An operator fixes both, hence 409.
  NO_TRANSPORT: 409,
  DEVICE_BUSY: 409,
  UNREACHABLE: 502,
  TIMEOUT: 504,
  AUTH_FAILED: 502,
  PERMISSION_DENIED: 502,
  TLS_PINNING_FAILED: 502,
  PROTOCOL_ERROR: 502,
  PARSE_ERROR: 502,
  RATE_LIMITED: 429,
  // The breaker refused to dial. Retrying later is the whole meaning of it.
  CIRCUIT_OPEN: 503,
};

function asAppError(err: unknown): AppError | null {
  // ── The refusal that runs FIRST was the one not mapped ──────────────────
  //
  // `collectRaw` enters `withAssertedDevice` → `assertTargetBinding(…, {
  // throwOnFailure: true })` before it reads anything, and every refusal in
  // there throws `BindingAssertionError`, which extends `Error` and not
  // `DriverError`. So the whole identity family — "no credential in the vault",
  // "the routeros_api transport is absent or disabled", and the identity mismatch
  // that simultaneously QUARANTINES the device — fell through to the generic
  // handler and reached the operator as `500 Internal server error`.
  //
  // That is the worst possible answer here: a 500 is the one status an operator
  // is expected to escalate, and the identity case in particular is a finding they
  // must see, not a server fault they should report. 409 — the device's
  // configuration is wrong, not the request — matching `NO_TRANSPORT` above.
  //
  // The message is safe to forward: `BindingAssertion.summary` is built from
  // the identity attributes it compared and carries no credential.
  if (err instanceof BindingAssertionError) {
    return new AppError(409, err.message);
  }
  if (!(err instanceof DriverError)) return null;
  const status = DRIVER_ERROR_STATUS[err.code];
  return status === undefined ? null : new AppError(status, err.message);
}

const compareQuery = z.object({
  from: z.string().regex(/^[0-9]{1,19}$/).optional(),
  to: z.string().regex(/^[0-9]{1,19}$/).optional(),
  scope: z.enum(['managed_only', 'full']).optional(),
  fuzzy: z.enum(['true', 'false']).optional(),
});

export const configController = {
  /** GET /api/config/devices/:deviceId/snapshots */
  async listSnapshots(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const q = parse(listQuery, req.query);
      // Serves both `/config/devices/:deviceId/snapshots` and the fleet-wide
      // `/config/snapshots`. `deviceId` may also arrive as a query parameter on
      // the latter; absent everywhere, the caller gets the whole tenant.
      const rawDeviceId = req.params.deviceId ?? (req.query.deviceId as string | undefined);
      const deviceId = rawDeviceId === undefined ? undefined : parseId(rawDeviceId, 'device id');
      // Team scope (084): only the snapshots of devices the caller's teams cover.
      const rows = await snapshots.listSnapshots(req.tenantId, deviceId, { ...q, deviceIdsIn: await deviceListScope(req) });
      res.json({ success: true, data: rows, ...godViewMeta(hasGlobalView(req)) });
    } catch (err) {
      next(err);
    }
  },

  /** GET /api/config/snapshots/:id — metadata only, no document. */
  async getSnapshot(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      // ── The DETAIL route carries the document; the LIST does not ─────────
      // This answered `getSnapshot()`, i.e. `SUMMARY_COLUMNS`, which does not
      // include `cs.ncm` — while the client normaliser reads `raw.ncm` and the
      // NCM-tree and Compare views are built on that document. So `ncm` was
      // ALWAYS null, and both views failed on a snapshot that had collected
      // perfectly. The `/snapshots/:id/ncm` route does serve a document, but a
      // grouped TREE, which `compareSnapshots()` cannot consume — two shapes,
      // and the client was asking a third.
      //
      // Heavy on the list, fine on the detail: this route returns ONE snapshot
      // and its whole reason for being opened is to look at its contents.
      // `getSnapshotDocument` also runs `upgradeNcm()` on read (stored
      // rows are never rewritten), so an old document arrives at the current
      // NCM version instead of confusing a renderer written against it.
      const loaded = await snapshots.getSnapshotDocument(
        req.tenantId,
        parseBigId(req.params.id, 'snapshot id'),
      );
      if (!loaded) throw new AppError(404, 'Snapshot not found');
      res.json({ success: true, data: { ...loaded.summary, ncm: loaded.doc } });
    } catch (err) {
      next(err);
    }
  },

  /**
   * GET /api/config/snapshots/:id/ncm — the NCM tree the UI renders.
   *
   * Grouped by resource kind and then by ORDER GROUP (chain), because a
   * firewall rendered as one flat 200-line list has positions that mean
   * nothing across chains.
   */
  async getNcmTree(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const tree = await snapshots.getNcmTree(
        req.tenantId,
        parseBigId(req.params.id, 'snapshot id'),
      );
      if (!tree) throw new AppError(404, 'Snapshot not found');
      res.json({ success: true, data: tree });
    } catch (err) {
      if (err instanceof NcmVersionAheadError) {
        // A row written by a newer server during a rollback. Refusing is the
        // only honest answer: a partially-understood document rendered as if
        // complete is worse than an error.
        next(new AppError(409, err.message));
        return;
      }
      next(err);
    }
  },

  /** GET /api/config/snapshots/:id/export — the redacted raw export, as text. */
  async exportSnapshot(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const raw = await snapshots.getSnapshotRaw(
        req.tenantId,
        parseBigId(req.params.id, 'snapshot id'),
      );
      if (!raw) throw new AppError(404, 'Snapshot not found, or it carries no raw archive');
      res.type('text/plain; charset=utf-8');
      res.setHeader('X-Obliwan-Raw-Sha256', raw.sha256 ?? '');
      res.setHeader(
        'Content-Disposition',
        `attachment; filename="${raw.deviceName.replace(/[^\w.-]/g, '_')}-${raw.capturedAt}.rsc"`,
      );
      res.send(raw.text);
    } catch (err) {
      next(err);
    }
  },

  /**
   * GET /api/config/devices/:deviceId/compare — N against N-1 by default.
   *
   * `scope` defaults to `managed_only` in the engine, and the response carries
   * `outOfScopeCount` so the operator can see what that default hid.
   */
  async compare(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const q = parse(compareQuery, req.query);
      const result = await snapshots.compareSnapshots(
        req.tenantId,
        parseId(req.params.deviceId, 'device id'),
        {
          fromId: q.from,
          toId: q.to,
          scope: q.scope,
          fuzzy: q.fuzzy === undefined ? undefined : q.fuzzy === 'true',
        },
      );
      if (!result) {
        throw new AppError(404, 'Not enough snapshots for this device to compare');
      }
      res.json({ success: true, data: result });
    } catch (err) {
      if (err instanceof NcmVersionAheadError) {
        next(new AppError(409, err.message));
        return;
      }
      next(err);
    }
  },

  /**
   * POST /api/config/devices/:deviceId/collect — read the box now.
   *
   * A READ of the equipment, never a write: it runs `/export terse
   * show-sensitive=no` and stores the result. It still opens a connection, so
   * it sits behind `CONFIG_WRITE` rather than `CONFIG_READ` — an operator
   * entitled to look at stored configuration is not thereby entitled to make
   * the platform dial a customer's router.
   *
   * It runs `collectAndStore`, the SAME entry point the scheduled drift
   * collection and the intervention snapshot use. A button on its own code path
   * would be exercising something the fleet never does.
   *
   * The interesting answer is `data.snapshot.created`. `false` is a SUCCESS: the
   * document was byte-identical to one already stored, so `UNIQUE(device_id,
   * ncm_hash)` confirmed the existing row and bumped `seen_count` instead of
   * inserting. Callers must word the two differently or a stable fleet reads as
   * a broken collector.
   */
  async collect(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const deviceId = parseId(req.params.deviceId, 'device id');
      // Rule 2 of this file, and the same order `reindex` uses: ownership is
      // established at the HTTP boundary so a foreign or deleted id is a 404
      // rather than an acquisition failure. Below this line every refusal is a
      // statement about a device the caller is entitled to ask about.
      if (!(await getDevice(req.tenantId, deviceId))) throw new AppError(404, 'Device not found');
      if (!hasNormalizer()) {
        throw new AppError(
          503,
          'No NCM normaliser is registered on this build; collection is refused rather than ' +
            'storing an empty document',
        );
      }
      const result = await collectAndStore(deviceId, req.tenantId, { source: 'ssh' });
      res.json({ success: true, data: result });
    } catch (err) {
      if (err instanceof NoNormalizerError) {
        next(new AppError(503, err.message));
        return;
      }
      if (err instanceof SensitiveMaterialError) {
        // No secrets: the message names the PROP and never the value.
        next(new AppError(422, err.message));
        return;
      }
      const mapped = asAppError(err);
      next(mapped ?? err);
    }
  },

  /**
   * POST /api/config/tenant-collect — collect EVERY collectable router of the
   * client (platform administrators only, behind `requireRole('admin')`).
   * Read-only: the same `collectAndStore` door as "Collect now", one router
   * after another (2 at once), the ones the scheduler would skip skipped. 202
   * with the progress; GET polls it. From the god view the client is the one
   * picked in the workspace filter, and none picked is a 400.
   */
  async startTenantCollect(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      requirePickedTenant(req);
      const state = await startTenantCollect(req.tenantId, req.session?.userId ?? null);
      res.status(202).json({ success: true, data: state });
    } catch (err) {
      next(err);
    }
  },

  /** GET /api/config/tenant-collect — the progress (null: none since boot). */
  async tenantCollect(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      requirePickedTenant(req);
      res.json({ success: true, data: tenantCollectState(req.tenantId) });
    } catch (err) {
      next(err);
    }
  },

  /** POST /api/config/snapshots/:id/reindex — rebuild the flattened cache. */
  async reindex(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const id = parseBigId(req.params.id, 'snapshot id');
      // Ownership is checked through the tenant-scoped read BEFORE the rebuild,
      // which itself is a raw id lookup.
      const owned = await snapshots.getSnapshot(req.tenantId, id);
      if (!owned) throw new AppError(404, 'Snapshot not found');
      const result = await reindexSnapshot(id);
      res.json({ success: true, data: result });
    } catch (err) {
      next(err);
    }
  },
};
