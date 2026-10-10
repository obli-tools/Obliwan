import { Router } from 'express';
import { requireAuth } from '../middleware/auth';
import { requireRole } from '../middleware/rbac';
import type { Request, Response } from 'express';
import { permissionSetService, PermissionSetError } from '../services/permissionSet.service';
import { logger } from '../utils/logger';

const router = Router();

/**
 * Since migration 084 the sets ARE the tenant roles and the runtime grants
 * what their rows list: every write below is a grant (or a revocation) for
 * every holder in every tenant. Platform admin only, audited by the service,
 * and every refusal answered with its reason (PermissionSetError) rather than
 * a bare 500.
 */
function actorOf(req: Request): { userId: number | null; username: string | null } {
  return { userId: req.session.userId ?? null, username: req.session.username ?? null };
}

function fail(res: Response, err: unknown, fallback: string): void {
  if (err instanceof PermissionSetError) {
    res.status(err.status).json({ success: false, error: err.message });
    return;
  }
  logger.error(err, fallback);
  res.status(500).json({ success: false, error: fallback });
}

/**
 * The two read routes below were `requireAuth` alone, while
 * the three write routes were already `requireRole('admin')`.
 *
 * What leaked is not data belonging to a customer, so this is cartography rather
 * than a breach: `GET /` returns every permission set with its full capability
 * list, and `GET /capabilities` returns the complete catalogue of capability
 * names the build knows about. Any authenticated account — including one with no
 * `user_tenants` row at all, which 403s on every other route in the product —
 * could read the exact vocabulary of the authorisation system and the exact
 * shape of each role, which is the map you want before looking for a gap in it.
 *
 * Restricting them costs nothing: the ONLY consumer of either route is
 * `client/src/components/PermissionSetsTab.tsx` (both are fetched together in
 * one `Promise.all`, line 48-49), which is a tab of `AdminUsersPage` — a screen
 * whose other calls already go to `/api/users`, i.e. behind `requireRole('admin')`
 * already. Nothing else in the client or the server references them.
 */

/**
 * GET /api/permission-sets
 * Returns all permission sets. Platform admins only (see above).
 */
router.get('/', requireAuth, requireRole('admin'), async (_req, res) => {
  try {
    const sets = await permissionSetService.getAll();
    res.json({ success: true, data: sets });
  } catch (err) {
    logger.error(err, 'Failed to list permission sets');
    res.status(500).json({ success: false, error: 'Failed to list permission sets' });
  }
});

/**
 * GET /api/permission-sets/capabilities
 * Returns available capabilities for this app. Platform admins only (see above).
 */
router.get('/capabilities', requireAuth, requireRole('admin'), async (_req, res) => {
  try {
    const capabilities = permissionSetService.getAvailableCapabilities();
    res.json({ success: true, data: capabilities });
  } catch (err) {
    logger.error(err, 'Failed to list capabilities');
    res.status(500).json({ success: false, error: 'Failed to list capabilities' });
  }
});

/**
 * POST /api/permission-sets
 * Creates a new permission set. Admin only.
 */
router.post('/', requireAuth, requireRole('admin'), async (req, res) => {
  try {
    const { name, slug, description, capabilities } = (req.body ?? {}) as {
      name?: string; slug?: string; description?: string | null; capabilities?: unknown;
    };
    const set = await permissionSetService.create(
      { name: name ?? '', slug, description, capabilities: capabilities ?? [] },
      actorOf(req),
    );
    res.status(201).json({ success: true, data: set });
  } catch (err) {
    fail(res, err, 'Failed to create permission set');
  }
});

/**
 * PUT /api/permission-sets/:id
 * Updates a permission set. Admin only.
 */
router.put('/:id', requireAuth, requireRole('admin'), async (req, res) => {
  try {
    const id = parseInt(req.params.id, 10);
    if (isNaN(id)) { res.status(400).json({ success: false, error: 'Invalid ID' }); return; }
    const { name, slug, description, capabilities } = (req.body ?? {}) as {
      name?: string; slug?: string; description?: string | null; capabilities?: unknown;
    };
    const set = await permissionSetService.update(id, { name, slug, description, capabilities }, actorOf(req));
    res.json({ success: true, data: set });
  } catch (err) {
    fail(res, err, 'Failed to update permission set');
  }
});

/**
 * POST /api/permission-sets/:id/reset
 * A builtin role back to the seed of migration 084. Admin only, audited.
 */
router.post('/:id/reset', requireAuth, requireRole('admin'), async (req, res) => {
  try {
    const id = parseInt(req.params.id, 10);
    if (isNaN(id)) { res.status(400).json({ success: false, error: 'Invalid ID' }); return; }
    const set = await permissionSetService.reset(id, actorOf(req));
    res.json({ success: true, data: set });
  } catch (err) {
    fail(res, err, 'Failed to reset permission set');
  }
});

/**
 * DELETE /api/permission-sets/:id
 * Deletes a non-default permission set. Admin only.
 */
router.delete('/:id', requireAuth, requireRole('admin'), async (req, res) => {
  try {
    const id = parseInt(req.params.id, 10);
    if (isNaN(id)) { res.status(400).json({ success: false, error: 'Invalid ID' }); return; }
    await permissionSetService.delete(id, actorOf(req));
    res.json({ success: true });
  } catch (err) {
    fail(res, err, 'Failed to delete permission set');
  }
});

export default router;
