import { Router, type NextFunction, type Request, type Response } from 'express';
import { CAPABILITIES } from '@obliwan/shared';
import { requireCapability } from '../middleware/rbac';
import { AppError } from '../middleware/errorHandler';
import { godViewMeta, hasGlobalView } from '../utils/globalView';
import { deviceListScope } from '../services/teamScope.service';
import {
  getOperatorOutage,
  listOperatorOutages,
  type OutageScope,
} from '../services/fleet/operatorOutage.service';

/**
 * The grouped operator outages (migration 095,
 * services/fleet/operatorOutage.service.ts). Read only: the groups are opened
 * and closed by the leader's sweep, never by a request.
 *
 * WHO SEES WHAT. The god view (a platform admin on the master tenant) sees a
 * group spanning every tenant, each store with its tenant. Anyone else sees
 * the groups that hold at least one store of its tenant that its teams cover,
 * with THOSE stores and THEIR count only — never another customer's stores or
 * counts; a group with none of them answers 404, like an id that never
 * existed. DEVICE_READ, the 4G backup list's capability.
 */
const router = Router();

async function scopeOf(req: Request): Promise<OutageScope> {
  const godView = hasGlobalView(req);
  return { godView, tenantId: req.tenantId, deviceIdsIn: godView ? null : await deviceListScope(req) };
}

router.get('/', requireCapability(CAPABILITIES.DEVICE_READ), async (req: Request, res: Response, next: NextFunction) => {
  try {
    const raw = typeof req.query.status === 'string' ? req.query.status : undefined;
    if (raw !== undefined && raw !== 'open' && raw !== 'closed') throw new AppError(400, 'status: open ou closed');
    const scope = await scopeOf(req);
    const items = await listOperatorOutages(scope, { status: raw as 'open' | 'closed' | undefined });
    res.json({ success: true, data: items, ...godViewMeta(scope.godView) });
  } catch (err) {
    next(err);
  }
});

router.get('/:id', requireCapability(CAPABILITIES.DEVICE_READ), async (req: Request, res: Response, next: NextFunction) => {
  try {
    const id = Number(req.params.id);
    if (!Number.isSafeInteger(id) || id <= 0) throw new AppError(404, 'Panne opérateur introuvable');
    const scope = await scopeOf(req);
    const detail = await getOperatorOutage(scope, id);
    if (!detail) throw new AppError(404, 'Panne opérateur introuvable');
    res.json({ success: true, data: detail, ...godViewMeta(scope.godView) });
  } catch (err) {
    next(err);
  }
});

export default router;
