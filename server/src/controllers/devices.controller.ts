import type { EnrollDeviceInput } from '../validators/device.schema';
import type { BenchEnrolmentInput } from '../middleware/benchEnrolment';
import type { Request, Response, NextFunction } from 'express';
import { CAPABILITIES, FAMILY_BRAND, type Capability, type DeviceFamily, type TransportKind } from '@obliwan/shared';
import { AppError } from '../middleware/errorHandler';
import { logger } from '../utils/logger';
import * as deviceService from '../services/fleet/device.service';
import { toDeviceDetailDto, toDeviceDto } from '../services/fleet/dto';
import {
  assertTargetBinding,
  BindingAssertionError,
  learnDeviceFacts,
} from '../services/fleet/deviceBinding.service';
import { pppPresence } from '../services/fleet/pppPresence.service';
import { assessDevice } from '../services/fleet/reachability.service';
import { VaultError } from '../services/secretVault.service';
import { diagnoseDevice } from '../services/fleet/diagnose.service';
import { checkDeviceNow, healthCheckView } from '../services/fleet/healthCheck.service';
import { assessUplink } from '../services/fleet/uplink.service';
import { backup4gDeviceView, backup4gFleet } from '../services/fleet/backup4g.service';
import { withStoreProviders } from '../services/fleet/operatorOutage.service';
import { permissionService } from '../services/permission.service';
import { accessOf, accessOfOne, deviceListScope } from '../services/teamScope.service';
import {
  findSerialHolder,
  isBrandSerialCollision,
  judgeEnrolmentRetry,
  recordEnrolmentStation,
} from '../services/bench/stations.service';
import { assertApprovedBenchStation } from '../middleware/benchStation';
import { actedFromGodView, godViewMeta, hasGlobalView, tenantNames } from '../utils/globalView';
import type {
  CreateConcentratorInput,
  CreateDeviceInput,
  UpdateDeviceInput,
  UpsertTransportInput,
} from '../validators/device.schema';

/**
 * Devices — HTTP layer.
 *
 * The response shapes come from `device.service.ts`, which is the only module
 * allowed to serialise a transport. Nothing in this file selects from
 * `device_transports` directly; that is how "no secret ever leaves through the
 * API" stays true after the fifth person edits this controller.
 *
 * Every device row is mapped by `services/fleet/dto.ts` before it reaches
 * `res.json()`. The columns are `snake_case`, the API contract is `camelCase`,
 * and the conversion happens at this edge and nowhere else. Transports keep
 * their own serialiser, `toPublicTransport()`, which is what guarantees
 * `hasSecret` / `hasPrivateKey` in place of `secret_enc` / `private_key_enc` —
 * encrypted or not, the blob never crosses this boundary (section 8.2).
 */

function parseId(raw: string, what = 'id'): number {
  const id = Number.parseInt(raw, 10);
  if (!Number.isInteger(id) || id <= 0) throw new AppError(400, `Invalid ${what}`);
  return id;
}

/** Does the caller hold `capability` on the tenant it operates on? The same
 *  rule as `requireCapability` (platform admins pass), for a route that shows
 *  MORE to a caller who holds it rather than refusing one who does not. */
async function callerHolds(req: Request, capability: Capability): Promise<boolean> {
  if (!req.session?.userId) return false;
  if (req.session.role === 'admin') return true;
  const tenantId = req.tenantId ?? req.session.currentTenantId;
  if (!tenantId) return false;
  const caps = await permissionService.getUserCapabilities(req.session.userId, false, tenantId);
  return caps.includes(capability);
}

/**
 * Who is writing, for the one device-service rule that asks
 * (`DeviceWriteOptions`, the PPP-username claim). `req.session.role` is the
 * role `requireAuth` revalidated against the database — through its identity
 * cache, so at most REVALIDATE_MS (10 s) old — the same expression
 * `requireTenant` and `requireCapability` trust. Without it the service treats
 * every caller as a tenant, and a platform administrator was refused with a
 * message saying only a platform administrator may do this.
 */
function deviceWriteOptions(req: Request): deviceService.DeviceWriteOptions {
  return { platformAdmin: req.session?.role === 'admin' };
}

/** The plain `Error`s `assertReferencesInTenant` throws for a bad reference.
 *  The shared-concentrator refusals are `AppError`s and pass through as they
 *  are (400 / 403). */
const BAD_REFERENCE = /does not exist in this tenant|its own concentrator|not a concentrator/;

function pgCode(err: unknown): string | undefined {
  return typeof err === 'object' && err !== null ? (err as { code?: string }).code : undefined;
}

/** Turn the constraints of migration 002 into operator-readable answers. */
function translateDbError(err: unknown): AppError | null {
  const code = pgCode(err);
  const detail =
    typeof err === 'object' && err !== null ? String((err as { detail?: string }).detail ?? '') : '';

  if (code === '23505') {
    if (detail.includes('ppp_username')) {
      return new AppError(409, 'This PPP username is already bound to another device');
    }
    if (detail.includes('brand') && detail.includes('serial')) {
      return new AppError(409, 'A device with this brand and serial already exists');
    }
    return new AppError(409, 'A device with these unique attributes already exists');
  }
  if (code === '23503') {
    // FK RESTRICT — the concentrator still has children (this is on purpose:
    // deleting it would orphan the presence source of truth for a whole fleet).
    return new AppError(
      409,
      'This device is still referenced by other devices (a concentrator with attached CPEs cannot be deleted)',
    );
  }
  return null;
}

/**
 * Enrolment's own translator, and the reason it exists.
 *
 * ┌─ A 500 IS A STATEMENT ABOUT THE SERVER, AND IT WAS A LIE HERE ───────────┐
 * │ `POST /devices/enroll-probe` used to end in a bare `next(err)`. Every     │
 * │ failure it could have — a vault that cannot encrypt, a serial that is     │
 * │ already somebody else's, a site in another tenant — reached the operator  │
 * │ as `500 Internal server error`, which is the one status a human is        │
 * │ expected to escalate. A misconfigured key and a typo'd serial produced    │
 * │ the same three words, so neither could be acted on and both looked like   │
 * │ the product being broken.                                                 │
 * │                                                                          │
 * │ The neighbouring `create` handler has translated its errors since day     │
 * │ one; this route is the newer of the two and simply never got the same     │
 * │ treatment. `errorHandler.ts` makes exactly this argument in its own       │
 * │ header about foreign keys.                                                │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * `VaultError` is a 503, not a 500: the request was correct, the SERVER cannot
 * honour it yet. Its message is safe to forward — it names the environment
 * variable and how to generate one, and by construction it never carries a
 * secret or a ciphertext (section 8.2).
 */
function translateEnrolError(err: unknown): AppError | null {
  if (err instanceof VaultError) {
    return new AppError(
      503,
      `The credential vault refused to store this password. ${err.message}`,
    );
  }
  const db = translateDbError(err);
  if (db) return db;
  if (err instanceof Error && err.message.includes('does not exist in this tenant')) {
    return new AppError(400, err.message);
  }
  return null;
}

const DEFAULT_ENROL_TRANSPORT: Readonly<Record<string, TransportKind>> = {
  mikrotik_routeros6: 'routeros_api',
  mikrotik_routeros7: 'routeros_api',
  draytek_vigor: 'ssh',
  zyxel_standalone: 'ssh',
  zyxel_nebula: 'rest',
  zyxel_cpe: 'ssh',
  sonicwall_sonicos: 'rest',
};

export const devicesController = {
  async list(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const q = req.query as Record<string, unknown>;
      const accessFor = await accessOf(req, 'device');
      const result = await deviceService.listDevices(req.tenantId, {
        siteId: q.siteId as number | undefined,
        role: q.role as string | undefined,
        status: q.status as string | undefined,
        brand: q.brand as string | undefined,
        family: q.family as string | undefined,
        concentratorId: q.concentratorId as number | undefined,
        search: q.search as string | undefined,
        limit: q.limit as number | undefined,
        offset: q.offset as number | undefined,
        // Team scope (084): only the devices the caller's teams cover.
        deviceIdsIn: await deviceListScope(req),
      });
      res.json({
        success: true,
        // `access`: 'ro' | 'rw' per row from the caller's teams (migration 087).
        data: result.items.map((d) => ({ ...toDeviceDto(d), access: accessFor(d.id) })),
        meta: { total: result.total },
        ...godViewMeta(result.godView),
      });
    } catch (err) {
      next(err);
    }
  },

  async getById(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const id = parseId(req.params.id);
      const device = await deviceService.getDeviceDetail(req.tenantId, id);
      if (!device) throw new AppError(404, 'Device not found');
      // The permanent health check, with the interval / retries / alert delay
      // that apply to THIS device now (resolved through the settings chain), so
      // the page states what is enforced rather than what the defaults say.
      const healthCheck = await healthCheckView(req.tenantId, id);
      // Opened from the god view (any tenant's device): say whose it is.
      const tenantName = actedFromGodView(req) || hasGlobalView(req)
        ? (await tenantNames([device.tenant_id])).get(Number(device.tenant_id)) ?? null
        : undefined;
      res.json({
        success: true,
        data: {
          ...toDeviceDetailDto(device),
          healthCheck,
          access: await accessOfOne(req, 'device', id),
          ...(tenantName !== undefined ? { tenantName } : {}),
        },
      });
    } catch (err) {
      next(err);
    }
  },

  async create(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const body = req.body as CreateDeviceInput;
      const device = await deviceService.createDevice(
        req.tenantId,
        {
          ...body,
          family: body.family as DeviceFamily,
          role: body.role as 'cpe' | 'concentrator' | undefined,
          status: body.status as CreateDeviceInput['status'],
        } as deviceService.CreateDeviceData,
        deviceWriteOptions(req),
      );
      res.status(201).json({ success: true, data: toDeviceDto(device) });
    } catch (err) {
      const translated = translateDbError(err);
      if (translated) return next(translated);
      // Same mapping as `update`. This handler used to match only "does not
      // exist in this tenant", so a CPE pointed at a device of its own tenant
      // that is not a concentrator left as a bare 500.
      if (err instanceof Error && !(err instanceof AppError) && BAD_REFERENCE.test(err.message)) {
        return next(new AppError(400, err.message));
      }
      next(err);
    }
  },

  /**
   * Declare the concentrator — the first gesture of an ObliWAN install.
   *
   * Creates the `devices` row (role `chr`) and its `routeros_api` transport in
   * one transaction-shaped call, then immediately tests the credential. A CHR
   * that was declared but never verified is worse than no CHR: discovery would
   * silently return nothing and read as "an empty fleet".
   */
  async createConcentrator(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const body = req.body as CreateConcentratorInput;
      const family = body.family as DeviceFamily;
      if (FAMILY_BRAND[family] !== 'mikrotik') {
        throw new AppError(400, 'The concentrator must be a MikroTik: only RouterOS serves /ppp/active');
      }

      const device = await deviceService.createDevice(req.tenantId, {
        name: body.name,
        family,
        role: 'concentrator',
        siteId: body.siteId ?? null,
        systemIdentity: body.systemIdentity ?? null,
        notes: body.notes ?? null,
        // A concentrator is active as soon as it answers; it is not a discovered
        // CPE waiting for a human to place it.
        status: 'active',
      });

      await deviceService.upsertTransport(req.tenantId, device.id, 'routeros_api', {
        enabled: true,
        priority: 10,
        host: body.host,
        port: body.port ?? null,
        username: body.username,
        secret: body.password,
        useTls: body.useTls ?? false,
        tlsFingerprintSha256: body.tlsFingerprintSha256 ?? null,
      });

      const test = await deviceService.testTransport(req.tenantId, device.id, 'routeros_api');
      if (test.ok && test.identity?.systemIdentity) {
        await deviceService.updateDevice(req.tenantId, device.id, {
          systemIdentity: test.identity.systemIdentity,
          serial: test.identity.serial ?? undefined,
        });
      }

      const detail = await deviceService.getDeviceDetail(req.tenantId, device.id);
      res.status(201).json({
        success: true,
        data: {
          device: detail ? toDeviceDetailDto(detail) : null,
          connection: test,
        },
      });
    } catch (err) {
      const translated = translateDbError(err);
      if (translated) return next(translated);
      next(err);
    }
  },

  /**
   * Approve a `pending` device — the per-device human gate of the quarantine.
   *
   * ┌─ THE DEVICE'S AUTHORISATION. THE BENCH STATION'S IS A SEPARATE ONE ──────┐
   * │ `POST /devices/enroll` is NOT anonymous: it demands the `Bench <token>`  │
   * │ of a workstation a platform administrator approved                      │
   * │ (`requireApprovedBenchStation`, middleware/benchStation.ts; approval at  │
   * │ `POST /api/bench-stations/:id/approve`). That approval says "this desk   │
   * │ may file boxes", once, and nothing about any one box — so what a bench   │
   * │ files still lands `pending` and unmanaged in the master tenant (a UI     │
   * │ enrolment lands `pending` too, in the caller's tenant). This route is    │
   * │ the second gate, per device: "this box is who it says". Without it the   │
   * │ quarantine is a list nobody can empty.                                   │
   * └──────────────────────────────────────────────────────────────────────────┘
   *
   * ONE EXCEPTION, by explicit design: a box a bench COMPILED a
   * file for (`bench_provisionings`) may instead be confirmed by the automatic
   * conformity check, `services/fleet/autoConfirm.service.ts`, under the exact
   * conditions listed in `deviceBinding.service.ts` (header box). Every other
   * `pending` device — an enrolment, a hand-declared one — waits for this
   * route, and so does a bench box the check could not confirm.
   *
   * It sets `status` only. `is_managed` stays as it was — false for anything a
   * bench filed — and that column, not this one, is what `enqueueChangeJob`
   * checks before a write job (`device_not_managed`).
   *
   * Refuses without an identity, and that refusal is the point rather than a
   * formality: `assertTargetBinding` corroborates a device against its recorded
   * `serial` / `system_identity`, and with neither it answers "unproven, fail
   * closed" for the rest of that device's life. Approving into that state would
   * hand an operator an `active` device that silently refuses every collection
   * and every write — the product looking broken instead of the row looking
   * incomplete.
   *
   * `pending` only. Re-approving an `active` device is a no-op an operator did
   * not mean, and a `quarantined` one got there because its identity was
   * CONTRADICTED — clearing that needs somebody to look at why, not a
   * button that says approve.
   */
  async approve(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const id = parseId(req.params.id);
      const device = await deviceService.getDevice(req.tenantId, id);
      if (!device) throw new AppError(404, 'Device not found');

      if (device.status !== 'pending') {
        throw new AppError(
          409,
          device.status === 'quarantined'
            ? 'This device is QUARANTINED, not pending: it answered with an identity that '
              + 'contradicts its record. Find out why before returning it to the fleet — '
              + 'approving it here would bless whatever is now at that address.'
            : `This device is already '${device.status}'. Only a pending device is approved.`,
        );
      }

      if (!device.serial && !device.system_identity) {
        throw new AppError(
          409,
          'This device has neither a serial number nor a system identity, so nothing can ever '
          + 'corroborate that a box answering at its address IS this device. Approving it '
          + 'would create an active device that refuses every collection and every write. Read '
          + 'the identity with "Test connection", or type one on the Settings tab, then approve.',
        );
      }

      const updated = await deviceService.updateDevice(req.tenantId, id, { status: 'active' });
      logger.info(
        { deviceId: id, by: req.session?.userId ?? null, name: device.name },
        'Quarantined device approved',
      );
      res.json({ success: true, data: updated ? toDeviceDto(updated) : null });
    } catch (err) {
      next(err);
    }
  },

  async update(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const device = await deviceService.updateDevice(
        req.tenantId,
        parseId(req.params.id),
        req.body as UpdateDeviceInput as deviceService.UpdateDeviceData,
        deviceWriteOptions(req),
      );
      if (!device) throw new AppError(404, 'Device not found');
      res.json({ success: true, data: toDeviceDto(device) });
    } catch (err) {
      const translated = translateDbError(err);
      if (translated) return next(translated);
      if (err instanceof Error && !(err instanceof AppError) && BAD_REFERENCE.test(err.message)) {
        return next(new AppError(400, err.message));
      }
      next(err);
    }
  },

  async delete(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const id = parseId(req.params.id);
      const children = await deviceService.concentratorChildCount(req.tenantId, id);
      if (children > 0) {
        throw new AppError(
          409,
          `This concentrator still has ${children} device(s) attached. ` +
            'Re-attach or delete them first — deleting it would leave them with no presence source.',
        );
      }
      const ok = await deviceService.deleteDevice(req.tenantId, id);
      if (!ok) throw new AppError(404, 'Device not found');
      res.json({ success: true, message: 'Device deleted' });
    } catch (err) {
      const translated = translateDbError(err);
      if (translated) return next(translated);
      next(err);
    }
  },

  // ── Transports ────────────────────────────────────────────────────────────

  async listTransports(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const data = await deviceService.listTransports(req.tenantId, parseId(req.params.id));
      res.json({ success: true, data });
    } catch (err) {
      if (err instanceof Error && err.message.includes('does not exist')) {
        return next(new AppError(404, 'Device not found'));
      }
      next(err);
    }
  },

  async upsertTransport(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const data = await deviceService.upsertTransport(
        req.tenantId,
        parseId(req.params.id),
        req.params.transport as TransportKind,
        req.body as UpsertTransportInput,
      );
      res.json({ success: true, data });
    } catch (err) {
      if (err instanceof Error && err.message.includes('does not exist')) {
        return next(new AppError(404, 'Device not found'));
      }
      if (err instanceof Error && err.message.startsWith('Unknown transport')) {
        return next(new AppError(400, err.message));
      }
      next(err);
    }
  },

  async deleteTransport(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const ok = await deviceService.deleteTransport(
        req.tenantId,
        parseId(req.params.id),
        req.params.transport as TransportKind,
      );
      if (!ok) throw new AppError(404, 'Transport not found');
      res.json({ success: true, message: 'Transport deleted' });
    } catch (err) {
      if (err instanceof Error && err.message.includes('does not exist')) {
        return next(new AppError(404, 'Device not found'));
      }
      next(err);
    }
  },

  async testTransport(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const result = await deviceService.testTransport(
        req.tenantId,
        parseId(req.params.id),
        req.params.transport as TransportKind,
      );
      // A failed test is a legitimate answer, not an HTTP error: the operator
      // asked a question and got one.
      res.json({ success: true, data: result });
    } catch (err) {
      if (err instanceof Error && err.message.includes('does not exist')) {
        return next(new AppError(404, 'Device not found'));
      }
      next(err);
    }
  },

  /**
   * "Test this device" — every enabled channel, once.
   *
   * The channel-level `POST /:id/transports/:transport/test` answers "does
   * THIS credential work". This one answers "can we reach this box at all",
   * which is the question the detail page's button actually asks and the one
   * the client has always called. Both are kept: they are different questions
   * and a device with four channels deserves both answers.
   *
   * The payload is `{ deviceId, results: [...] }` — a named envelope, because
   * a bare array leaves no room for the device-level context this will grow
   * (the arbiter's refusal reasons).
   */
  async testConnection(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const id = parseId(req.params.id);
      const results = await deviceService.testAllTransports(req.tenantId, id);

      // ── The test already talked to the box; do not throw away what it said ──
      // Model, serial, OS version and system identity were on the wire during
      // the probe. Leaving the page showing "—" for a device the server just
      // reached is asking an operator to retype, by hand, facts the hardware
      // had already reported. Blanks only — see `learnDeviceFacts`.
      let learned: Awaited<ReturnType<typeof learnDeviceFacts>> | null = null;
      let learnError: string | null = null;
      if (results.some((r) => r.ok)) {
        try {
          learned = await learnDeviceFacts(req.tenantId, id);
        } catch (err) {
          // A failed second round trip must not turn a SUCCESSFUL test into an
          // error: the operator asked "can we reach it", and the answer is yes.
          //
          // But it must not vanish either. This used to end at `logger.warn`,
          // which meant the identity fields stayed empty on a device the server
          // had just talked to and NOTHING on any screen said why — the exact
          // shape of "the product is silently broken". The message is already
          // redacted by the driver layer, so it is safe to forward.
          learnError = err instanceof Error ? err.message.slice(0, 300) : String(err).slice(0, 300);
          logger.warn({ err, deviceId: id }, 'Could not learn device facts after a successful test');
        }
      }

      res.json({
        success: true,
        data: {
          deviceId: id,
          learned: learned && (Object.keys(learned.filled).length > 0 || learned.conflicts.length > 0)
            ? learned
            : null,
          // Non-null only when the identity read FAILED on a device the test
          // reached. Surfaced rather than logged: empty identity fields with no
          // explanation is the shape of a product that is silently broken.
          learnError,
          results: results.map((r) => ({
            transport: r.transport,
            ok: r.ok,
            rttMs: r.latencyMs,
            dialled: r.dialled,
            // Already redacted by the transport layer; never a credential.
            error: r.error,
          })),
        },
      });
    } catch (err) {
      if (err instanceof Error && err.message.includes('does not exist')) {
        return next(new AppError(404, 'Device not found'));
      }
      next(err);
    }
  },

  /**
   * "Check now" — one run of the permanent health check, immediately.
   *
   * DEVICE_WRITE, the capability of "Test connection": it opens a channel to a
   * customer's equipment, which is an operator act. Unlike the test, it goes
   * through the SAME code as the scheduler — the same channel choice, the same
   * rule (a CPE whose PPP session is down is not dialled), the same state
   * row and the same alerts — so what the button shows is what the scheduler
   * would have recorded.
   */
  async checkHealth(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const outcome = await checkDeviceNow(req.tenantId, parseId(req.params.id));
      if (outcome.kind === 'not_found') throw new AppError(404, 'Device not found');
      if (outcome.kind === 'disabled') {
        throw new AppError(
          409,
          "This device's status is 'disabled', so it is never checked. Set it back to pending or "
            + 'active first.',
        );
      }
      if (outcome.kind === 'aborted') {
        // Not the device's answer: ObliWAN could not run the check (vault,
        // target, shutdown). 503, never 401/403 — the client logs the
        // operator out on a 401, and this says nothing about their session.
        throw new AppError(503, `The check could not be run: ${outcome.reason}`);
      }
      res.json({ success: true, data: outcome.view });
    } catch (err) {
      next(err);
    }
  },

  /**
   * "It timed out — why?"
   *
   * DEVICE_WRITE, the same capability as the test it follows: this opens
   * sockets to a customer's equipment, which is an operator act, not a read.
   * The address is never taken from the request — see the service's header.
   */
  async diagnose(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const id = parseId(req.params.id);
      const result = await diagnoseDevice(req.tenantId, id);
      res.json({ success: true, data: result });
    } catch (err) {
      if (err instanceof Error && err.message.includes('does not exist in this tenant')) {
        return next(new AppError(404, 'Device not found'));
      }
      if (err instanceof Error && err.message.includes('no address to diagnose')) {
        return next(new AppError(409, err.message));
      }
      next(err);
    }
  },

  /**
   * Which WAN is this site actually on — measured, not configured.
   *
   * DEVICE_READ: it opens no socket and touches no equipment. Everything it
   * answers comes from samples and snapshots already collected, which is also
   * why it can answer instantly for 500 devices.
   */
  async uplink(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const deviceId = parseId(req.params.id);
      const verdict = await assessUplink(req.tenantId, deviceId);
      if (!verdict) throw new AppError(404, 'Device not found');
      // The 4G backup watch (migration 075). Decoration like the egress half:
      // it may never take the verdict down with it. The SIM line rides along
      // only for a caller holding SIM_READ.
      const backup4g = await backup4gDeviceView(req.tenantId, deviceId, {
        includeSim: await callerHolds(req, CAPABILITIES.SIM_READ),
      }).catch((err: unknown) => {
        logger.warn({ err, deviceId }, '4G backup view unreadable');
        return null;
      });
      res.json({ success: true, data: { ...verdict, backup4g } });
    } catch (err) {
      next(err);
    }
  },

  /**
   * "Sites on 4G backup": every router of the workspace whose active default
   * route is on its cellular link while the site has a fixed uplink. DEVICE_READ;
   * the SIM lines ride along only for a caller holding SIM_READ.
   */
  async backup4g(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const items = await backup4gFleet(req.tenantId, {
        includeSim: await callerHolds(req, CAPABILITIES.SIM_READ),
        // Team scope (087): the routers the caller's teams cover.
        deviceIdsIn: await deviceListScope(req),
      });
      // The fixed line's provider and its evidence, and the operator outage
      // the store is grouped under (migration 095): the list's provider column.
      const withProvider = await withStoreProviders(items, req.tenantId);
      res.json({ success: true, data: withProvider, ...godViewMeta(hasGlobalView(req)) });
    } catch (err) {
      next(err);
    }
  },

  // ── Identity, presence, history ───────────────────────────────────────────

  /**
   * Re-prove the device's identity on a FRESH connection.
   *
   * Exposed as an explicit operator action so the assertion can be exercised
   * before the safe write gives it teeth. A failure is a 409, not a 500: the box answered,
   * it is simply not the box we recorded.
   */
  async assertBinding(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const id = parseId(req.params.id);
      const device = await deviceService.getDevice(req.tenantId, id);
      if (!device) throw new AppError(404, 'Device not found');

      const assertion = await assertTargetBinding(id, { throwOnFailure: false });
      if (!assertion.ok) {
        res.status(409).json({ success: false, error: assertion.reason, data: assertion });
        return;
      }
      res.json({ success: true, data: assertion });
    } catch (err) {
      if (err instanceof BindingAssertionError) {
        res.status(409).json({
          success: false,
          error: err.assertion.reason,
          data: err.assertion,
        });
        return;
      }
      next(err);
    }
  },

  async sessions(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const data = await deviceService.deviceSessions(req.tenantId, parseId(req.params.id));
      res.json({ success: true, data });
    } catch (err) {
      if (err instanceof Error && err.message.includes('does not exist')) {
        return next(new AppError(404, 'Device not found'));
      }
      next(err);
    }
  },

  async reachability(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const id = parseId(req.params.id);
      const device = await deviceService.getDevice(req.tenantId, id);
      if (!device) throw new AppError(404, 'Device not found');
      const [history, current] = await Promise.all([
        deviceService.deviceVerdicts(req.tenantId, id),
        assessDevice(id),
      ]);
      res.json({ success: true, data: { current, history } });
    } catch (err) {
      next(err);
    }
  },

  /** Force a full `/ppp/active` sweep on a concentrator, now. */
  async reconcile(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const id = parseId(req.params.id);
      const device = await deviceService.getDevice(req.tenantId, id);
      if (!device) throw new AppError(404, 'Device not found');
      if (device.role !== 'concentrator') throw new AppError(400, 'This device is not a concentrator');
      const result = await pppPresence.reconcileNow(id);
      res.json({ success: true, data: result });
    } catch (err) {
      next(err);
    }
  },

  /** Which concentrators this process is streaming from, if it is the leader. */
  async presenceStatus(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const ids = await deviceService.concentratorIdsForTenant(req.tenantId);
      res.json({
        success: true,
        data: {
          running: pppPresence.isRunning,
          watched: pppPresence.watched.filter((id) => ids.includes(id)),
          concentrators: ids,
        },
      });
    } catch (err) {
      next(err);
    }
  },

  /**
   * Single-device enrolment FROM THE UI (second path).
   *
   * ┌─ THE SAME QUARANTINE, THE OPPOSITE SECRET POLICY ──────────────────────┐
   * │ Like the bench path, the device lands `pending` and unmanaged: a row an │
   * │ operator typed is a CLAIM about a box, and a claim is confirmed on a    │
   * │ fresh connection before anything is pushed.                             │
   * │                                                                        │
   * │ Unlike the bench path, a credential IS transmitted — this is the one    │
   * │ ObliWAN will keep — so it goes straight to the vault and this route     │
   * │ demands `CREDENTIAL_MANAGE` of an operator session. The bench path has  │
   * │ no session at all: it is authenticated by an approved workstation's     │
   * │ token and carries no credential. Different caller, different payload,   │
   * │ which is why they are two routes and not one route with a flag.        │
   * └────────────────────────────────────────────────────────────────────────┘
   *
   * The probe runs AFTER the transport is stored, because `testTransport`
   * reads the vault rather than taking a password as an argument — the same
   * path a real operation will use. Probing with the value from the request
   * body would prove that THIS password works, not that the stored one does,
   * and those two differ the day an encryption key is wrong.
   *
   * A probe that reads no identity does NOT delete the row. The operator can
   * see it, fix the credential and retry; and `pending` + unmanaged already
   * means nothing will WRITE to it. The permanent health check does read it —
   * one API read per interval, behind the pool's breaker, which opens on the
   * first refused credential — and that is how the page keeps saying whether
   * the corrected credential works. Silently discarding what somebody typed is
   * a worse failure than leaving a row they can correct.
   */
  async enrollFromUi(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const body = req.body as EnrollDeviceInput;
      const family = body.family as DeviceFamily;
      const transport = (body.transport ?? DEFAULT_ENROL_TRANSPORT[family] ?? 'ssh') as TransportKind;

      const device = await deviceService.createDevice(
        req.tenantId,
        {
          name: body.name,
          family,
          role: (body.role as 'cpe' | 'concentrator' | undefined) ?? 'cpe',
          siteId: body.siteId ?? null,
          model: body.model ?? null,
          serial: body.serial ?? null,
          pppUsername: body.pppUsername ?? null,
          // Where to dial today, never an identity. Recorded because the
          // operator knows it and the transport host may differ.
          tunnelIp: body.tunnelIp ?? null,
          systemIdentity: null,
          notes: body.notes ?? null,
          // Not negotiable by the payload. A human binds it afterwards.
          status: 'pending',
        },
        // The form sends a PPP username and never a concentrator. A name with
        // no concentrator is still a claim (`decidePppClaim`, "NO CONCENTRATOR
        // IS NOT NO CLAIM"): a platform administrator records it, anybody else
        // gets a 403 here, before the credential below reaches the vault.
        deviceWriteOptions(req),
      );

      // ── The device row and its way in are ONE gesture ──────────────────────
      // Storing the credential is the step that fails first on a fresh install
      // (an absent or malformed OBLIWAN_ENCRYPTION_KEY makes `encrypt()`
      // throw), and until this compensation existed the failure left behind a
      // device nobody could dial and nobody had asked for. The operator then
      // retried with the same name and serial and was told the SERIAL was a
      // duplicate — of the ghost their own first attempt had created.
      try {
        await deviceService.upsertTransport(req.tenantId, device.id, transport, {
          enabled: true,
          priority: 10,
          host: body.host,
          port: body.port ?? null,
          username: body.username,
          secret: body.password,
          useTls: body.useTls ?? transport === 'rest',
          tlsFingerprintSha256: null,
        });
      } catch (err) {
        await deviceService.deleteDevice(req.tenantId, device.id).catch(() => undefined);
        throw err;
      }

      // Past this line a failure is a RESULT, not an error: the box was
      // unreachable, and the row stays with its answer recorded on it.
      const test = await deviceService.testTransport(req.tenantId, device.id, transport);
      if (test.ok && (test.identity?.systemIdentity || test.identity?.serial)) {
        await deviceService.updateDevice(req.tenantId, device.id, {
          systemIdentity: test.identity.systemIdentity ?? undefined,
          serial: test.identity.serial ?? undefined,
        });
      }

      const detail = await deviceService.getDeviceDetail(req.tenantId, device.id);
      res.status(201).json({
        success: true,
        data: {
          device: detail ? toDeviceDetailDto(detail) : null,
          connection: test,
          // Said out loud rather than left for the operator to discover on the
          // first push: without one of the two identity attributes,
          // `assertTargetBinding` refuses every write to this device.
          identityRead: Boolean(test.identity?.systemIdentity || test.identity?.serial),
        },
      });
    } catch (err) {
      next(translateEnrolError(err) ?? err);
    }
  },

  /**
   * Bench enrolment — an APPROVED workstation files a router it has on
   * its bench.
   *
   * ┌─ IT LANDS IN QUARANTINE, AND THE TENANT IS A SUGGESTION ───────────────┐
   * │ `status: 'pending'` and `is_managed: false`, whatever the payload says  │
   * │ — the bench tool does not even send them. This is the same quarantine   │
   * │ CHR discovery uses and for the same reason: the preparer                │
   * │ picked a customer from a dropdown, on a workbench, on their fortieth    │
   * │ box of the day. Get it wrong and customer A's variables render onto     │
   * │ customer B's router. So `proposedTenantId` is recorded as a NOTE and    │
   * │ binds nothing; a human confirms it in the UI with the identity the box  │
   * │ actually reported in front of them.                                     │
   * │                                                                        │
   * │ Nothing dials a device this endpoint creates. It has no credential —    │
   * │ the factory password never left the preparer's workstation.            │
   * └────────────────────────────────────────────────────────────────────────┘
   *
   * Reached only through `requireApprovedBenchStation` → `benchEnrolmentLimiter`
   * → `validate(benchEnrolmentSchema)` → `benchEnrolmentContext`, mounted in
   * `routes/index.ts` OUTSIDE `tenantRouter`. Under `tenantRouter` this handler
   * was unreachable: `requireAuth` answered 401 to every bench call first. So
   * the body arrives parsed and trimmed, and `req.benchStation` is an approved
   * desk. The serial-or-identity rule lives in that schema; the bench tool
   * refuses first, and a client-side check is a convenience, not a boundary.
   *
   * ── WHAT IS RECORDED, AND ONE THING THAT IS DELIBERATELY NOT ──────────────
   * `serial`, `model` and `os_version` are written as reported. They used to be
   * dropped: this handler wrote the system identity alone, so a box enrolled
   * with its serial in the payload landed without one — losing the attribute
   * that keeps the identity rule true across a reconfiguration.
   *
   * `system_identity` is written ONLY when the box reported no serial. On a
   * bench it is the vendor's factory default — every new RouterOS box answers
   * "MikroTik" — and the next thing that happens to the box is a configuration
   * that renames it. Recorded, it would be contradicted by the very push that
   * follows; `compareIdentity` treats one mismatch as fatal, so the device would
   * be quarantined on its first contact with the platform, and
   * `learnDeviceFacts()` never overwrites a filled column, so nothing would ever
   * correct it. Left empty, the first fresh connection after provisioning learns
   * the real name. The reported value goes into the notes, so nothing the box
   * said is lost. Without a serial it is the only handle a later connection has,
   * and then it IS recorded.
   *
   * The device NAME follows the same logic: "MikroTik" forty times in the
   * quarantine list is forty rows a human cannot tell apart while choosing which
   * one to approve. Model + serial is what is printed on the box's label.
   *
   * ── A RETRY IS NOT A CONFLICT ─────────────────────────────────────────────
   * Storing the serial made `devices_brand_serial_uniq` reachable from here. A
   * bench that lost the answer to its enrolment (a timeout, a Wi-Fi drop) and
   * retries collides with the row its own first call created. When that row is
   * still exactly what the first call wrote (`judgeEnrolmentRetry`), the answer
   * is 200 with that row's id, the same way `register` answers a repeated
   * registration. Any other collision is a 409 that names the next step and
   * never whose device it is.
   *
   * ── THE STATION STAMP IS BEST-EFFORT, NOT TRANSACTIONAL ────────────────────
   * The device row and its stamp (`devices.enrolled_by_station_id`) are TWO
   * writes. `createDevice` does its own INSERT and takes no transaction. If the
   * stamp fails, the row is deleted again. That compensation does not cover a
   * process that dies between the two writes, and the delete itself can fail;
   * a failed delete is logged at error level, not swallowed. Either way the
   * leftover row is pending, unmanaged and in the master tenant, and its notes
   * still name the station (`Station: … (#id`). It can be found with a text
   * search, but the column query a revocation relies on misses it. Closing that
   * gap means `CreateDeviceData` accepting the station id so the stamp rides in
   * the same INSERT, and that change belongs to `fleet/device.service.ts`.
   */
  async enroll(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      // Approved, not merely authenticated: `requireBenchStationSelf` also
      // sets `req.benchStation`, for a pending station.
      const station = assertApprovedBenchStation(req);
      const body = req.body as BenchEnrolmentInput;
      const id = body.identity;
      const serial = id.serial ?? null;
      const reportedIdentity = id.systemIdentity ?? null;
      const model = id.model ?? null;

      // The schema already refused this; restated so the name below needs no
      // cast, and so a mount that lost the validator still refuses it.
      const handle = serial ?? reportedIdentity;
      if (!handle) {
        throw new AppError(
          400,
          'The device reported neither a serial number nor a system identity. It cannot be '
            + 'recognised on a later connection, so it is not enrolled. Read the identity '
            + 'again on the bench, then retry the enrolment.',
        );
      }

      const provenance = [
        'Enrolled from a preparation bench.',
        `Station: ${station.name} (#${station.id}, approved).`,
        body.preparedBy ? `The workstation reports its hostname as ${body.preparedBy}.` : null,
        body.preparedAt ? `At: ${body.preparedAt}.` : null,
        serial && reportedIdentity
          ? `System identity reported on the bench: "${reportedIdentity}" — not recorded as `
            + 'identity, because the configuration that follows renames the box.'
          : null,
        // Recorded as text on purpose: a suggestion that lived in a foreign key
        // would be one migration away from becoming a binding.
        body.proposedTenantId ? `Tenant PROPOSED by the preparer: #${body.proposedTenantId} (not applied).` : null,
        body.note ? `Note: ${body.note}` : null,
      ].filter(Boolean).join(' ');

      let device: Awaited<ReturnType<typeof deviceService.createDevice>>;
      try {
        device = await deviceService.createDevice(req.tenantId, {
          name: (serial ? [model, serial].filter(Boolean).join(' ') : handle).slice(0, 255),
          family: id.family,
          role: 'cpe',
          siteId: null,
          model,
          serial,
          osVersion: id.osVersion ?? null,
          systemIdentity: serial ? null : reportedIdentity,
          notes: provenance,
          // The quarantine. Not negotiable by the payload.
          status: 'pending',
          isManaged: false,
        });
      } catch (err) {
        if (!serial || !isBrandSerialCollision(err)) throw err;
        const verdict = judgeEnrolmentRetry(
          await findSerialHolder(FAMILY_BRAND[id.family], serial),
          station.id,
          req.tenantId,
        );
        if (verdict.kind === 'same_enrolment') {
          logger.info(
            { stationId: station.id, deviceId: verdict.deviceId },
            'Bench enrolment repeated — answered with the device the first call created',
          );
          res.status(200).json({
            success: true,
            data: { deviceId: verdict.deviceId, status: 'pending' },
          });
          return;
        }
        // "Retry once" covers the one benign case that lands here: the first
        // call is still between its INSERT and its stamp, so its row is not
        // stamped yet. A retry after it finishes gets the 200 above. A genuine
        // conflict stays a 409 however often the bench retries.
        throw new AppError(
          409,
          'This serial number is already registered on the platform, and not as an enrolment '
            + 'this workstation has pending. Nothing was enrolled. If this workstation enrolled '
            + 'this box a moment ago, retry the enrolment once; otherwise ask an administrator to '
            + 'look the serial up in the device list, quarantine included.',
        );
      }

      try {
        await recordEnrolmentStation(req.tenantId, device.id, station.id);
      } catch (err) {
        try {
          await deviceService.deleteDevice(req.tenantId, device.id);
        } catch (cleanupErr) {
          logger.error(
            { err: cleanupErr, stampErr: err, deviceId: device.id, stationId: station.id },
            'Bench enrolment: the station stamp failed AND the compensating delete failed — a '
              + 'pending device without enrolled_by_station_id remains; its notes name the station',
          );
        }
        throw err;
      }

      res.status(201).json({
        success: true,
        data: { deviceId: device.id, status: 'pending' },
      });
    } catch (err) {
      // A `(brand, serial)` collision has already been answered above. What
      // `translateDbError` still sees here is any other constraint, and it
      // never says whose row was hit.
      next(translateDbError(err) ?? err);
    }
  },
};
