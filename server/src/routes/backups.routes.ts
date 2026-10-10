import { Router } from 'express';
import { CAPABILITIES } from '@obliwan/shared';
import { requireCapability } from '../middleware/rbac';
import { db } from '../db';
import { applyTenantScope, godViewMeta, tenantNames } from '../utils/globalView';
import { deviceListScope } from '../services/teamScope.service';

/**
 * Pre-change backups — READ ONLY, and deliberately not everything.
 *
 * ┌─ WHAT THIS ROUTE REFUSES TO EXPOSE, AND WHY ─────────────────────────────┐
 * │ `device_backups` carries two columns this API will never return:          │
 * │                                                                          │
 * │   `encryption_password_enc`  the key to the archive. The secrets rule: a  │
 * │   secret                                                                  │
 * │                              exists in memory on the vault → device path  │
 * │                              and nowhere else. It is not selected here —  │
 * │                              not redacted, ABSENT, so no future refactor  │
 * │                              can leak it by widening a `select('*')`.     │
 * │   `storage_path`             a server-side filesystem path. Publishing it │
 * │                              buys an operator nothing and hands a reader  │
 * │                              the layout of the backup store.              │
 * │                                                                          │
 * │ There is also NO DOWNLOAD ENDPOINT. A backup is a device's complete       │
 * │ configuration; streaming it into a browser turns a controlled artefact    │
 * │ into a file in a Downloads folder, on a laptop, forever. If a human ever  │
 * │ needs the bytes, that is a deliberate server-side operation with a name,  │
 * │ not a link on a list — and none exists today.                             │
 * │                                                                          │
 * │ NOTHING LOADS A STORED BACKUP ONTO A ROUTER EITHER. The `restore` change  │
 * │ kind has no renderer and is refused at every door and at claim            │
 * │ (apply.service.ts, UNIMPLEMENTED_WRITE_KINDS): queued, it armed the       │
 * │ on-box dead-man and refused at the write, and the dead-man rebooted the   │
 * │ router for nothing. What a preflight backup does today is serve the       │
 * │ on-box dead-man of its own job, then stay here as a record. A change is   │
 * │ undone by pushing the configuration that preceded it — a rollout of the   │
 * │ previous template revision — never by loading a backup from this list.   │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * `CONFIG_READ` and not `DEVICE_READ`: knowing a device exists and reading its
 * configuration history are different privileges, and the capability model keeps them
 * apart precisely so config can be withheld.
 */
const router = Router();

router.get('/', requireCapability(CAPABILITIES.CONFIG_READ), async (req, res, next) => {
  try {
    const deviceId = req.query.deviceId ? Number(req.query.deviceId) : null;
    const limit = Math.min(Number(req.query.limit ?? 200), 500);

    let q = db('device_backups as b')
      .leftJoin('devices as d', 'd.id', 'b.device_id');
    // God view (a platform admin's GET on the master tenant): every tenant's
    // backups, each tagged with its tenant; anyone else: this tenant's.
    const godView = applyTenantScope(q, 'b.tenant_id', req.tenantId);
    if (deviceId) q = q.where('b.device_id', deviceId);
    // Team scope (migration 087): the backups of the devices the caller's teams cover.
    const teamIds = await deviceListScope(req);
    if (teamIds) q = q.whereIn('b.device_id', teamIds);

    const rows = await q
      .orderBy('b.created_at', 'desc')
      .limit(limit)
      .select(
        'b.id', 'b.device_id', 'b.kind', 'b.trigger_kind', 'b.size_bytes',
        'b.retention_class', 'b.expires_at', 'b.status', 'b.taken_before_job_id',
        'b.os_version', 'b.created_at', 'b.tenant_id',
        'd.name as device_name',
      );
    const names = godView ? await tenantNames(rows.map((r: Record<string, unknown>) => Number(r.tenant_id))) : null;

    res.json({
      success: true,
      ...godViewMeta(godView),
      data: rows.map((r: Record<string, unknown>) => ({
        ...(names ? { tenantId: Number(r.tenant_id), tenantName: names.get(Number(r.tenant_id)) ?? null } : {}),
        id: Number(r.id),
        deviceId: r.device_id === null ? null : Number(r.device_id),
        deviceName: (r.device_name as string | null) ?? null,
        kind: r.kind,
        triggerKind: r.trigger_kind,
        sizeBytes: Number(r.size_bytes ?? 0),
        retentionClass: r.retention_class,
        expiresAt: r.expires_at,
        status: r.status,
        takenBeforeJobId: r.taken_before_job_id === null ? null : Number(r.taken_before_job_id),
        osVersion: r.os_version,
        createdAt: r.created_at,
      })),
    });
  } catch (err) {
    next(err);
  }
});

export default router;
