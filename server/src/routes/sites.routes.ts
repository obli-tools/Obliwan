import { Router } from 'express';
import { CAPABILITIES } from '@obliwan/shared';
import { sitesController } from '../controllers/sites.controller';
import { requireCapability } from '../middleware/rbac';
import { refuseSiteScheduleChange } from '../middleware/siteSchedule';
import { validate } from '../middleware/validate';
import {
  bulkSiteFixedProviderSchema,
  bulkSiteUplinkKindSchema,
  createSiteSchema,
  deleteSiteQuerySchema,
  updateSiteSchema,
} from '../validators/site.schema';
import { godViewParam } from '../utils/globalView';
import { openingHoursController } from '../controllers/openingHours.controller';
import { bulkSiteOpeningHoursSchema, tenantOpeningHoursSchema } from '../validators/openingHours.schema';

/**
 * Sites. Mounted under the tenant-scoped router, so `requireAuth` and
 * `requireTenant` have already run.
 *
 * Reading the fleet is `DEVICE_READ`. Creating, editing and importing sites
 * is `SITE_WRITE`, which was carved out of `DEVICE_WRITE` for a role that
 * writes nothing to a device (the account manager); `DEVICE_WRITE` implies it.
 * Deleting a site stays `DEVICE_WRITE`. The push SCHEDULE of an existing
 * site — its maintenance window and timezone — is not customer data and still
 * needs `SITE_SCHEDULE_CAPABILITY` (DEVICE_WRITE): `refuseSiteScheduleChange`
 * on the edit, and on the import the timezone rule `importCsv` hands to
 * siteImport.service (`canWriteSchedule`). Config
 * reading is a DIFFERENT capability (`CONFIG_READ`) and appears
 * nowhere in this file — an operator who may see the inventory does not thereby
 * get to see the configurations.
 */
const router = Router();

// God view (utils/globalView.ts): a route naming ONE sites row by `:id`
// acts in that row's own tenant — read, write and audit alike. No-op for
// anyone but a platform admin positioned on the master tenant.
router.param('id', godViewParam('sites'));

router.get('/', requireCapability(CAPABILITIES.DEVICE_READ), sitesController.list);
/**
 * The deployment state of every site, and its Excel export. Same guard as the
 * list (the account manager following a rollout holds DEVICE_READ through the
 * operator and viewer sets); both before every `/:id` route, which would
 * otherwise read "deployment" as an id and refuse it.
 */
router.get('/deployment', requireCapability(CAPABILITIES.DEVICE_READ), sitesController.deployment);
router.get('/export.xlsx', requireCapability(CAPABILITIES.DEVICE_READ), sitesController.exportXlsx);
/**
 * Bulk import (CSV). Declared before every `/:id` route. The body is JSON
 * `{ csv, allocate? }` only, parsed by app.ts's `express.json({ limit: '1mb' })`
 * — that 1 MB is the real ceiling of a file. There is deliberately no
 * text/plain or text/csv parser here: those are CORS-safelisted types, so a
 * cross-origin page could send a credentialed import with no preflight, and
 * no client needs them. Variable values additionally need
 * SITE_VARIABLES_WRITE, a timezone change on an existing site
 * SITE_SCHEDULE_CAPABILITY, and `allocate` the platform admin — all checked
 * in the controller or the import service, because whether they are needed
 * depends on the file.
 */
router.get(
  '/import/template',
  requireCapability(CAPABILITIES.SITE_WRITE),
  sitesController.importTemplate,
);
router.post(
  '/import',
  requireCapability(CAPABILITIES.SITE_WRITE),
  sitesController.importCsv,
);
/**
 * One access-link declaration (migration 076) for many sites — "this whole
 * customer is 4G only" in one gesture. SITE_WRITE, like editing one site: it
 * changes what is alerted about a site, never what is written to a router.
 * Declared before every `/:id` route. All ids of the session's tenant, or
 * nothing is written.
 */
router.post(
  '/bulk/uplink-kind',
  requireCapability(CAPABILITIES.SITE_WRITE),
  validate(bulkSiteUplinkKindSchema),
  sitesController.bulkUplinkKind,
);
/**
 * « Opérateur du lien fixe » (migration 095) for many sites — the best
 * evidence of the grouped operator outage. SITE_WRITE: it changes how outages
 * are grouped and labelled, never what is written to a router. Declared
 * before every `/:id` route; all ids of the tenant, or nothing is written.
 */
router.post(
  '/bulk/fixed-provider',
  requireCapability(CAPABILITIES.SITE_WRITE),
  validate(bulkSiteFixedProviderSchema),
  sitesController.bulkFixedProvider,
);
/**
 * Store opening hours (migration 096). The workspace's usual hours, which
 * every site without a week of its own inherits, and one write for many
 * selected sites. SITE_WRITE like the rest of the customer record: the hours
 * change what is alerted and when, never what is written to a router.
 * Declared before every `/:id` route.
 */
router.get('/opening-hours', requireCapability(CAPABILITIES.DEVICE_READ), openingHoursController.getTenant);
router.put(
  '/opening-hours',
  requireCapability(CAPABILITIES.SITE_WRITE),
  validate(tenantOpeningHoursSchema),
  openingHoursController.putTenant,
);
router.post(
  '/bulk/opening-hours',
  requireCapability(CAPABILITIES.SITE_WRITE),
  validate(bulkSiteOpeningHoursSchema),
  openingHoursController.bulk,
);
router.get('/:id', requireCapability(CAPABILITIES.DEVICE_READ), sitesController.getById);
/**
 * What the site form and the delete dialog need and the site DTO does not
 * carry: the stored country, whether the code may still change, and what a
 * delete would leave behind (site.service `siteEditContext`). A forecast: the
 * rename and the delete judge again under their locks. Without this route the
 * form fails closed (code read-only, country never offered) and the dialog
 * cannot name what a delete must acknowledge.
 */
router.get('/:id/edit-context', requireCapability(CAPABILITIES.DEVICE_READ), sitesController.editContext);
router.get('/:id/presence', requireCapability(CAPABILITIES.DEVICE_READ), sitesController.presence);
/** The site's own inventory, filtered server-side. */
router.get('/:id/devices', requireCapability(CAPABILITIES.DEVICE_READ), sitesController.devices);
/** The PPP chronology of that inventory. */
router.get(
  '/:id/ppp-sessions',
  requireCapability(CAPABILITIES.DEVICE_READ),
  sitesController.pppSessions,
);

router.post(
  '/',
  requireCapability(CAPABILITIES.SITE_WRITE),
  validate(createSiteSchema),
  sitesController.create,
);
/**
 * The schedule guard sits AFTER `validate`: it compares the PARSED body with
 * the stored row, so a form sending the untouched schedule back passes.
 */
router.patch(
  '/:id',
  requireCapability(CAPABILITIES.SITE_WRITE),
  validate(updateSiteSchema),
  refuseSiteScheduleChange(),
  sitesController.update,
);
/**
 * `?acknowledge=chr_account,bench_history,sla_history` names what the caller
 * knows will remain outside ObliWAN's hold or be lost (site.schema
 * `SITE_DELETE_ACKNOWLEDGEMENTS`); the service refuses 409 while one it finds
 * is not named.
 */
router.delete(
  '/:id',
  requireCapability(CAPABILITIES.DEVICE_WRITE),
  validate(deleteSiteQuerySchema, 'query'),
  sitesController.delete,
);

export default router;
