import type { Request, Response, NextFunction } from 'express';
import type { DeviceFamily } from '@obliwan/shared';
import { db } from '../db';
import { AppError } from '../middleware/errorHandler';
import {
  assertDiscoveryBindAllowed,
  bindDiscovery,
  getDiscovery,
  listDiscoveries,
  runChrDiscovery,
  setDiscoveryState,
} from '../services/fleet/concentratorDiscovery.service';
import * as deviceService from '../services/fleet/device.service';
import { toDeviceDetailDto, toDiscoveryDto } from '../services/fleet/dto';
import type { BindDiscoveryInput } from '../validators/device.schema';
import { actedFromGodView, godViewMeta, hasGlobalView, withTenantNames } from '../utils/globalView';

/**
 * Discoveries — the quarantine review screen.
 *
 * `discoveries` has NO `tenant_id` (migration 002): a PPP username seen on the
 * wire belongs to nobody until a human says so. Scoping therefore goes through
 * the CONCENTRATOR: a caller sees the discoveries of the concentrators in their
 * tenant, and nothing else. That is why every handler that reads a discovery
 * starts by resolving the tenant's concentrator ids instead of filtering on a
 * column.
 *
 * Binding is the only path from `pending` to `bound`, it requires
 * `DEVICE_DISCOVER` and `DEVICE_WRITE`, and it stamps `reviewed_by`. There is
 * no auto-bind, no "bind all", and no heuristic on tunnel IP — that is risk
 * The identity-binding risk, and the whole reason this screen exists.
 *
 * VISIBLE IS NOT REVIEWABLE. The operator's shared CHR is a concentrator of
 * the MASTER tenant, so every member of tenant 1 sees its discoveries — every
 * customer's dialled site — because that is where platform administrators
 * review them. Both gestures on such a row take a platform administrator:
 * binding it (`decideDiscoveryBind`), and ignoring it or returning it to
 * `pending` (`decideDiscoveryReview`), since an ignored row never comes back
 * on a re-scan. On a tenant's own concentrator, binding takes a device of that
 * same tenant. The rules and their reasons are in
 * fleet/concentratorDiscovery.service.ts; the service applies both inside its
 * own transaction, from the reviewer's `users` row.
 */

function parseId(raw: string, what = 'id'): number {
  const id = Number.parseInt(raw, 10);
  if (!Number.isInteger(id) || id <= 0) throw new AppError(400, `Invalid ${what}`);
  return id;
}

/** Load a discovery and prove the caller's tenant owns its concentrator. */
async function requireVisibleDiscovery(req: Request, id: number) {
  const discovery = await getDiscovery(id);
  if (!discovery) throw new AppError(404, 'Discovery not found');
  const visible = await deviceService.concentratorIdsForTenant(req.tenantId);
  // A god-view request that moved into a target device's tenant (bind to a
  // customer's device, `godViewBodyTenant`) still sees what the god view saw:
  // the master tenant's shared concentrators. The bind rule itself
  // (`decideDiscoveryBind`) is unchanged and decides inside its transaction.
  if (actedFromGodView(req) && req.godViewFromTenantId !== undefined) {
    visible.push(...(await deviceService.concentratorIdsForTenant(req.godViewFromTenantId)));
  }
  if (!visible.includes(discovery.concentrator_id)) {
    // 404, not 403: the existence of another tenant's quarantine row is itself
    // information about another customer's fleet.
    throw new AppError(404, 'Discovery not found');
  }
  return discovery;
}

export const discoveriesController = {
  async list(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const q = req.query as Record<string, unknown>;
      let concentratorIds = await deviceService.concentratorIdsForTenant(req.tenantId);
      if (q.concentratorId !== undefined) {
        const wanted = Number(q.concentratorId);
        concentratorIds = concentratorIds.filter((id) => id === wanted);
      }
      const result = await listDiscoveries({
        concentratorIds,
        state: q.state as string | undefined,
        search: q.search as string | undefined,
        limit: q.limit as number | undefined,
        offset: q.offset as number | undefined,
      });
      // God view: each row says whose it is — the bound device's tenant, else
      // the concentrator's (the shared CHR's discoveries read "Default" until
      // a platform admin binds them).
      const godView = hasGlobalView(req);
      const dtos = result.items.map((r) => ({
        ...toDiscoveryDto(r),
        ...(godView ? { tenantId: Number(r.bound_tenant_id ?? r.concentrator_tenant_id) } : {}),
      }));
      res.json({
        success: true,
        data: await withTenantNames(dtos, 'tenantId', godView),
        meta: { total: result.total },
        ...godViewMeta(godView),
      });
    } catch (err) {
      next(err);
    }
  },

  /**
   * Run a discovery pass against a concentrator, now.
   *
   * Synchronous on purpose at this scale: the operator pressed a button and
   * wants the count back. It reads `/ppp/secret` and `/ppp/active` through the
   * single pooled socket, so two operators pressing it at once still produce
   * one round trip's worth of load on the CHR.
   */
  async scan(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const { concentratorId } = req.body as { concentratorId: number };
      const chr = await deviceService.getDevice(req.tenantId, concentratorId);
      if (!chr) throw new AppError(404, 'Concentrator not found');
      if (chr.role !== 'concentrator') throw new AppError(400, 'This device is not a concentrator');

      const result = await runChrDiscovery(concentratorId);
      res.json({ success: true, data: result });
    } catch (err) {
      if (err instanceof Error && err.message.includes('no usable RouterOS API transport')) {
        return next(new AppError(400, err.message));
      }
      next(err);
    }
  },

  async getById(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const discovery = await requireVisibleDiscovery(req, parseId(req.params.id));
      res.json({ success: true, data: toDiscoveryDto(discovery) });
    } catch (err) {
      next(err);
    }
  },

  /**
   * The human gesture: attach a quarantined PPP username to a device.
   *
   * Either an existing device, or one created on the spot from the operator's
   * own description of it. Note what the created device does NOT inherit from
   * the discovery: nothing about identity beyond the username. Model, serial
   * and system identity are learned from the box itself by
   * `assertTargetBinding()`, never from what the CHR happened to report.
   */
  async bind(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const discovery = await requireVisibleDiscovery(req, parseId(req.params.id));
      const body = req.body as BindDiscoveryInput;
      const userId = req.session.userId;
      if (!userId) throw new AppError(401, 'Authentication required');

      // Judged BEFORE the target device is resolved or created, so that none
      // of these refusals leaves the `device` branch's new row behind,
      // `pending` and bound to nothing:
      //  - the authority rule (both branches below put the device in
      //    `req.tenantId`);
      //  - a discovery already bound (a stale screen, a second click);
      //  - for a device created on the spot, a username another device holds
      //    (`devices.ppp_username` is UNIQUE platform-wide, and the bind's
      //    write would answer the same 409 after the device existed).
      // `bindDiscovery` judges the first two again inside its transaction,
      // under the discovery's row lock, and the UNIQUE index judges the third;
      // those are the judgements that decide. What only the write can see — a
      // concurrent bind of the same discovery or of the same name committing
      // between here and there — still leaves a created device behind:
      // `createDevice` commits on its own (fleet/device.service.ts), so this
      // handler cannot roll it back with the bind.
      await assertDiscoveryBindAllowed({
        concentratorId: discovery.concentrator_id,
        deviceTenantId: req.tenantId,
        reviewedBy: userId,
      });
      if (discovery.state === 'bound') {
        throw new AppError(
          409,
          `Discovery ${discovery.id} is already bound to device ${discovery.bound_device_id}`,
        );
      }

      let deviceId: number;
      if (body.deviceId !== undefined) {
        const device = await deviceService.getDevice(req.tenantId, body.deviceId);
        if (!device) throw new AppError(404, 'Target device not found in this tenant');
        deviceId = device.id;
      } else if (body.device) {
        const holder = await db('devices')
          .where({ ppp_username: discovery.ppp_username })
          .first<{ id: number } | undefined>('id');
        if (holder) throw new AppError(409, 'This PPP username is already bound to another device');
        const created = await deviceService.createDevice(req.tenantId, {
          ...(body.device as unknown as deviceService.CreateDeviceData),
          family: body.device.family as DeviceFamily,
          // Bound but unproven: `active` is a statement about a box that has
          // answered an identity assertion, and nothing has yet.
          status: 'pending',
        });
        deviceId = created.id;
      } else {
        throw new AppError(400, 'Provide either deviceId or device');
      }

      const bound = await bindDiscovery(discovery.id, deviceId, userId);
      const detail = await deviceService.getDeviceDetail(req.tenantId, deviceId);
      res.json({
        success: true,
        data: {
          discovery: toDiscoveryDto(bound),
          device: detail ? toDeviceDetailDto(detail) : null,
        },
      });
    } catch (err) {
      // An AppError already carries its status (the 403 of the bind rule among
      // them); the text matching below is for the service's plain Errors only.
      if (err instanceof AppError) return next(err);
      if (typeof err === 'object' && err !== null && (err as { code?: string }).code === '23505') {
        return next(new AppError(409, 'This PPP username is already bound to another device'));
      }
      if (err instanceof Error && /already bound|already bound to PPP user|does not exist/.test(err.message)) {
        return next(new AppError(409, err.message));
      }
      next(err);
    }
  },

  /**
   * Ignore (not ours) or push back to pending. Never used to unbind.
   *
   * Gated like binding: on the shared CHR only a platform administrator may
   * move a row, and `setDiscoveryState` decides it inside its transaction
   * (`decideDiscoveryReview`) — so the 403 comes from the service, not from
   * here.
   */
  async setState(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const discovery = await requireVisibleDiscovery(req, parseId(req.params.id));
      const { state } = req.body as { state: 'pending' | 'ignored' };
      const userId = req.session.userId;
      if (!userId) throw new AppError(401, 'Authentication required');
      const row = await setDiscoveryState(discovery.id, state, {
        reviewedBy: userId,
        actingTenantId: req.tenantId,
      });
      res.json({ success: true, data: toDiscoveryDto(row) });
    } catch (err) {
      if (err instanceof AppError) return next(err);
      if (err instanceof Error && err.message.includes('is bound to device')) {
        return next(new AppError(409, err.message));
      }
      next(err);
    }
  },
};
