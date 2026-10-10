import type { Request, Response, NextFunction } from 'express';
import { AppError } from '../middleware/errorHandler';
import * as siteService from '../services/fleet/site.service';
import * as deviceService from '../services/fleet/device.service';
import { toDeviceDto, toSiteDto } from '../services/fleet/dto';
import {
  SiteImportFileError,
  SiteImportForbiddenError,
  describeImportTemplate,
  importSites,
  isIanaTimeZone,
} from '../services/fleet/siteImport.service';
import {
  DEFAULT_EXPORT_TIME_ZONE,
  PPP_DOWN_GRACE_MIN,
  SITE_DEPLOYMENT_STATES,
  exportSitesXlsx,
  listSiteDeployments,
  toDeploymentDto,
  type SiteDeploymentFilters,
  type SiteDeploymentState,
} from '../services/fleet/siteDeployment.service';
import { XLSX_CONTENT_TYPE } from '../services/fleet/xlsx';
import { siteHoursContext, siteOpenStates } from '../services/fleet/openingHours.service';
import { permissionService } from '../services/permission.service';
import { callerHasCapability } from '../middleware/rbac';
import { accessOf, accessOfOne, deviceListScope, visibleSiteIdSet } from '../services/teamScope.service';
import { auditGodViewFanOut } from '../services/godViewAudit.service';
import { actedFromGodView, fanOutByTenant, godViewMeta, hasGlobalView, tenantNames } from '../utils/globalView';
import { BENCH_TUNNEL_WINDOW_MIN, CAPABILITIES, SITE_SCHEDULE_CAPABILITY } from '@obliwan/shared';
import type {
  BulkSiteFixedProviderInput,
  BulkSiteUplinkKindInput,
  CreateSiteInput,
  DeleteSiteQuery,
  UpdateSiteInput,
} from '../validators/site.schema';

/** Who acts, from the SESSION (never the body): the access-link stamp and
 *  the audit entry. */
function actorOf(req: Request): siteService.SiteActor {
  return {
    userId: req.session?.userId ?? null,
    username: req.session?.username ? req.session.username.slice(0, 128) : null,
  };
}

/** `?name=true|false`; absent gives `fallback`, anything else is a 400. */
function queryFlag(raw: unknown, name: string, fallback: boolean): boolean {
  if (raw === undefined) return fallback;
  if (raw === 'true') return true;
  if (raw === 'false') return false;
  throw new AppError(400, `${name} must be "true" or "false"`);
}

/**
 * Sites — HTTP layer.
 *
 * The tenant is ALWAYS `req.tenantId` (from the session, via `requireTenant`)
 * and never anything the client sent. A 404 rather than a 403 on a
 * cross-tenant id is deliberate: telling an operator "that site exists but is
 * not yours" is itself a leak of another customer's inventory.
 *
 * Every response body goes through a mapper from `services/fleet/dto.ts`. The
 * database columns are `snake_case` and the API contract is `camelCase`;
 * handing a Knex row to `res.json()` publishes the schema and silently breaks
 * every consumer, which is exactly what had happened here.
 */

function parseId(raw: string, what = 'id'): number {
  const id = Number.parseInt(raw, 10);
  if (!Number.isInteger(id) || id <= 0) throw new AppError(400, `Invalid ${what}`);
  return id;
}

const SEARCH_MAX = 200;

/**
 * `?search=` and `?state=a,b` of the deployment list and its export — the
 * page's own filters, so the file holds what the screen shows. A value is never
 * echoed back in a refusal.
 */
function deploymentFilters(query: Request['query']): SiteDeploymentFilters {
  const { search, state } = query;
  if (search !== undefined && typeof search !== 'string') {
    throw new AppError(400, 'search must be given once, as text');
  }
  if (typeof search === 'string' && search.length > SEARCH_MAX) {
    throw new AppError(400, `search is longer than ${SEARCH_MAX} characters`);
  }
  if (state !== undefined && typeof state !== 'string') {
    throw new AppError(400, 'state must be given once, as a comma-separated list');
  }
  const states = (state ?? '')
    .split(',')
    .map((s) => s.trim())
    .filter((s) => s !== '');
  for (const s of states) {
    if (!(SITE_DEPLOYMENT_STATES as readonly string[]).includes(s)) {
      throw new AppError(400, `state must be a comma-separated list of: ${SITE_DEPLOYMENT_STATES.join(', ')}`);
    }
  }
  return { search: search?.trim() || undefined, states: states as SiteDeploymentState[] };
}

/** Postgres unique-violation, turned into something an operator can act on. */
function isUniqueViolation(err: unknown): boolean {
  return typeof err === 'object' && err !== null && (err as { code?: string }).code === '23505';
}

export const sitesController = {
  async list(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const search = typeof req.query.search === 'string' ? req.query.search : undefined;
      // The SIM column: only for a caller who may read the lines (SIM_READ),
      // counted within the caller's team scope — the same lines the 4G page
      // lists when the count is clicked. Without SIM_READ the field is absent.
      const simCount = (await callerHasCapability(req, CAPABILITIES.SIM_READ))
        ? { deviceIds: await deviceListScope(req) }
        : undefined;
      const all = await siteService.listSites(req.tenantId, { search, simCount });
      // Team scope (084): only the sites the caller's teams cover.
      const visible = await visibleSiteIdSet(req);
      const sites = visible ? all.filter((s) => visible.has(Number(s.id))) : all;
      const accessFor = await accessOf(req, 'site');
      // « Ouvert / Fermé maintenant » (opening hours, migration 096).
      const openStates = await siteOpenStates(sites.map((s) => Number(s.id)));
      res.json({
        success: true,
        data: sites.map((s) => ({ ...toSiteDto(s), access: accessFor(s.id), openState: openStates.get(Number(s.id)) })),
        ...godViewMeta(hasGlobalView(req)),
      });
    } catch (err) {
      next(err);
    }
  },

  /**
   * GET /sites/deployment[?search=&state=] — the deployment state of every
   * site of the tenant (services/fleet/siteDeployment.service.ts). A sibling
   * of the list rather than a field of it: the list's shape is unchanged for
   * its other consumers (the fleet tree, the stores), and the state costs one
   * query the list does not need.
   */
  async deployment(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const rows = await listSiteDeployments(req.tenantId, {
        ...deploymentFilters(req.query),
        siteIds: await visibleSiteIdSet(req), // team scope (084)
      });
      const accessFor = await accessOf(req, 'site');
      res.json({
        success: true,
        data: rows.map((r) => ({ ...toDeploymentDto(r), access: accessFor(r.siteId) })),
        ...godViewMeta(hasGlobalView(req)),
        meta: {
          generatedAt: new Date().toISOString(),
          pppDownGraceMinutes: PPP_DOWN_GRACE_MIN,
          benchTunnelWindowMinutes: BENCH_TUNNEL_WINDOW_MIN,
        },
      });
    } catch (err) {
      next(err);
    }
  },

  /**
   * GET /sites/export.xlsx[?search=&state=&tz=] — the same rows as a real
   * Excel workbook, French headers. `tz` (IANA) is the zone the dates are
   * written in, defaulting to Europe/Paris: an Excel date carries no zone.
   *
   * The file name is built from the tenant's slug and the date only — nothing
   * the caller typed reaches the header. No secret is in the file: the PPP
   * password column is never read (see the service header).
   */
  async exportXlsx(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const filters = deploymentFilters(req.query);
      const tzRaw = req.query.tz;
      if (tzRaw !== undefined && (typeof tzRaw !== 'string' || !isIanaTimeZone(tzRaw))) {
        throw new AppError(400, 'tz must be an IANA time zone name (e.g. Europe/Paris)');
      }
      const { buffer, fileName } = await exportSitesXlsx(req.tenantId, { ...filters, siteIds: await visibleSiteIdSet(req) }, {
        timeZone: typeof tzRaw === 'string' ? tzRaw : DEFAULT_EXPORT_TIME_ZONE,
      });
      res.setHeader('Content-Type', XLSX_CONTENT_TYPE);
      res.setHeader('Content-Disposition', `attachment; filename="${fileName}"`);
      res.setHeader('Cache-Control', 'no-store');
      res.send(buffer);
    } catch (err) {
      next(err);
    }
  },

  async getById(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const site = await siteService.getSite(req.tenantId, parseId(req.params.id));
      if (!site) throw new AppError(404, 'Site not found');
      // Opened from the god view (any tenant's site): say whose it is.
      const tenantName = actedFromGodView(req) || hasGlobalView(req)
        ? (await tenantNames([site.tenant_id])).get(Number(site.tenant_id)) ?? null
        : undefined;
      res.json({
        success: true,
        data: {
          ...toSiteDto(site),
          // Opening hours (096): open now, what it inherits, and whether its
          // closed hours are its maintenance window.
          ...(await siteHoursContext(site)),
          access: await accessOfOne(req, 'site', Number(site.id)),
          ...(tenantName !== undefined ? { tenantName } : {}),
        },
      });
    } catch (err) {
      next(err);
    }
  },

  async create(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const site = await siteService.createSite(req.tenantId, req.body as CreateSiteInput, {
        actor: actorOf(req),
      });
      res.status(201).json({ success: true, data: toSiteDto(site) });
    } catch (err) {
      if (isUniqueViolation(err)) {
        next(new AppError(409, 'A site with this code already exists in this tenant'));
        return;
      }
      next(err);
    }
  },

  async update(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const site = await siteService.updateSite(
        req.tenantId,
        parseId(req.params.id),
        req.body as UpdateSiteInput,
        { actor: actorOf(req) },
      );
      if (!site) throw new AppError(404, 'Site not found');
      res.json({ success: true, data: toSiteDto(site) });
    } catch (err) {
      if (isUniqueViolation(err)) {
        next(new AppError(409, 'A site with this code already exists in this tenant'));
        return;
      }
      next(err);
    }
  },

  /**
   * POST /sites/bulk/uplink-kind — `{ ids, uplinkKind }`: one access-link
   * declaration (migration 076) for many sites of the session's tenant. Same
   * capability as editing one site (SITE_WRITE, checked by the route). Every
   * id must be a site of `req.tenantId` or nothing is written (404); the
   * service audits the request.
   */
  async bulkUplinkKind(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const body = req.body as BulkSiteUplinkKindInput;
      // God view: the selection may span tenants — one ordinary per-tenant
      // batch per owning tenant (each all-or-nothing and audited in its
      // tenant), plus one summary row in the master tenant.
      const { godView, batches } = await fanOutByTenant(req, 'sites', body.ids, (tid, ids) =>
        siteService.bulkSetSiteUplinkKind(tid, ids, body.uplinkKind, actorOf(req)));
      if (!godView) {
        res.json({ success: true, data: batches[0].result });
        return;
      }
      await auditGodViewFanOut(req, 'site.uplink_kind.bulk', batches, { uplinkKind: body.uplinkKind });
      const sum = (pick: (r: siteService.SiteUplinkBulkResult) => number) =>
        batches.reduce((n, b) => n + pick(b.result), 0);
      res.json({
        success: true,
        godView: true,
        data: {
          uplinkKind: body.uplinkKind,
          requested: sum((r) => r.requested),
          changed: sum((r) => r.changed),
          unchanged: sum((r) => r.unchanged),
          changedSiteIds: batches.flatMap((b) => b.result.changedSiteIds).sort((a, b) => a - b),
          backupAlertsClosed: sum((r) => r.backupAlertsClosed),
          byTenant: batches.map((b) => ({ tenantId: b.tenantId, requested: b.result.requested, changed: b.result.changed })),
        },
      });
    } catch (err) {
      next(err);
    }
  },

  /**
   * POST /sites/bulk/fixed-provider — `{ ids, fixedProvider }`: one
   * « Opérateur du lien fixe » (migration 095) for many sites. SITE_WRITE (the
   * route); all ids of the tenant or nothing (404); audited by the service. In
   * the god view, one ordinary per-tenant batch per owning tenant.
   */
  async bulkFixedProvider(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const body = req.body as BulkSiteFixedProviderInput;
      const { godView, batches } = await fanOutByTenant(req, 'sites', body.ids, (tid, ids) =>
        siteService.bulkSetSiteFixedProvider(tid, ids, body.fixedProvider, actorOf(req)));
      if (!godView) {
        res.json({ success: true, data: batches[0].result });
        return;
      }
      await auditGodViewFanOut(req, 'site.fixed_provider.bulk', batches, { fixedProvider: body.fixedProvider });
      const sum = (pick: (r: siteService.SiteFixedProviderBulkResult) => number) =>
        batches.reduce((n, b) => n + pick(b.result), 0);
      res.json({
        success: true,
        godView: true,
        data: {
          fixedProvider: body.fixedProvider,
          requested: sum((r) => r.requested),
          changed: sum((r) => r.changed),
          unchanged: sum((r) => r.unchanged),
          changedSiteIds: batches.flatMap((b) => b.result.changedSiteIds).sort((a, b) => a - b),
          byTenant: batches.map((b) => ({ tenantId: b.tenantId, requested: b.result.requested, changed: b.result.changed })),
        },
      });
    } catch (err) {
      next(err);
    }
  },

  /**
   * GET /sites/:id/edit-context — the stored country, the code lock and what a
   * delete would leave behind (site.service `siteEditContext`). Same 404 as a
   * site of another tenant.
   */
  async editContext(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const ctx = await siteService.siteEditContext(req.tenantId, parseId(req.params.id));
      if (!ctx) throw new AppError(404, 'Site not found');
      res.json({ success: true, data: ctx });
    } catch (err) {
      next(err);
    }
  },

  /**
   * DELETE /sites/:id[?acknowledge=chr_account,bench_history,sla_history] —
   * the acknowledgements were parsed by the route (`deleteSiteQuerySchema`);
   * the service refuses 409 while something it finds is not named. Answers
   * the report (what was released, kept and deleted): the dialog names the
   * concentrator account that stays from it. The actor comes from the session.
   */
  async delete(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const { acknowledge } = req.query as unknown as DeleteSiteQuery;
      const report = await siteService.deleteSite(req.tenantId, parseId(req.params.id), {
        acknowledge: acknowledge ?? [],
        actor: actorOf(req),
      });
      if (!report) throw new AppError(404, 'Site not found');
      res.json({ success: true, message: 'Site deleted', data: report });
    } catch (err) {
      next(err);
    }
  },

  /** Live presence of every device on the site, with its latest reachability verdict. */
  async presence(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const id = parseId(req.params.id);
      const site = await siteService.getSite(req.tenantId, id);
      if (!site) throw new AppError(404, 'Site not found');
      res.json({ success: true, data: await siteService.sitePresence(req.tenantId, id) });
    } catch (err) {
      next(err);
    }
  },

  /**
   * The devices filed under this site.
   *
   * The site detail page used to fetch the WHOLE fleet and filter it in the
   * browser. That is wrong twice over: it is O(fleet) to render one site, and
   * a truncated device list (the collection endpoint is paginated) silently
   * renders a site as emptier than it is. The server owns the filter.
   *
   * The 404 comes first, and it is the same 404 a site of another tenant
   * gets — otherwise this route becomes an existence oracle for ids the caller
   * is not allowed to name.
   */
  async devices(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const id = parseId(req.params.id);
      const site = await siteService.getSite(req.tenantId, id);
      if (!site) throw new AppError(404, 'Site not found');
      const result = await deviceService.listDevices(req.tenantId, { siteId: id, deviceIdsIn: await deviceListScope(req) });
      const accessFor = await accessOf(req, 'device');
      res.json({
        success: true,
        data: result.items.map((d) => ({ ...toDeviceDto(d), access: accessFor(d.id) })),
        meta: { total: result.total },
      });
    } catch (err) {
      next(err);
    }
  },

  /** PPP chronology for the site. */
  async pppSessions(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const id = parseId(req.params.id);
      const site = await siteService.getSite(req.tenantId, id);
      if (!site) throw new AppError(404, 'Site not found');
      const limitRaw = Number(req.query.limit);
      const limit = Number.isInteger(limitRaw) && limitRaw > 0 ? Math.min(limitRaw, 500) : 100;
      res.json({
        success: true,
        data: await siteService.sitePppSessions(req.tenantId, id, limit),
      });
    } catch (err) {
      next(err);
    }
  },

  /**
   * GET /sites/import/template — what a CSV template is built from: the fixed
   * columns and every declared variable the site form accepts (key, label,
   * secrecy, type). Never a value.
   */
  async importTemplate(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      res.json({ success: true, data: await describeImportTemplate(req.tenantId) });
    } catch (err) {
      next(err);
    }
  },

  /**
   * POST /sites/import?dryRun=true|false[&allocate=true|false]
   *
   * Body: `{ csv: string, allocate?: boolean }` as JSON only (see the route
   * for why there is no raw-text body). `dryRun` defaults to TRUE: a request that
   * forgot the flag reports instead of writing.
   *
   * SITE_WRITE is checked by the route. Variable values additionally need
   * SITE_VARIABLES_WRITE (the site form's capability) — asked here, and only
   * when the file actually carries a value. Moving an EXISTING site's timezone
   * needs SITE_SCHEDULE_CAPABILITY, as the PATCH route's
   * `refuseSiteScheduleChange` does: the import service turns it into a row
   * error, so the rest of the file still goes through. `allocate` reserves addresses in
   * pools that may be SHARED between tenants (and may dial the concentrator
   * to refresh a stale /ppp/secret read), so it is held to the platform
   * admin, like every allocation route (`allocation.routes.ts`).
   *
   * The dry run compares the rows with the CHR's last recorded read for a
   * platform admin (whole) or a holder of RECONCILE_READ (redacted, refused
   * under a template that names no tenant); anybody else gets the dry run
   * without a `chr` field. Never a refusal, and nothing is dialled.
   */
  async importCsv(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const dryRun = queryFlag(req.query.dryRun, 'dryRun', true);
      const body = req.body as unknown;
      let csv: unknown;
      let allocate = queryFlag(req.query.allocate, 'allocate', false);
      if (body && typeof body === 'object') {
        csv = (body as { csv?: unknown }).csv;
        const a = (body as { allocate?: unknown }).allocate;
        if (a !== undefined) {
          if (typeof a !== 'boolean') throw new AppError(400, 'allocate must be a boolean');
          allocate = allocate || a;
        }
      }
      if (typeof csv !== 'string' || csv.trim() === '') {
        throw new AppError(400, 'Send the CSV text as JSON: { "csv": "..." }.');
      }

      const isAdmin = req.session.role === 'admin';
      if (allocate && !isAdmin) {
        throw new AppError(403, 'Allocating addresses during an import is reserved to a platform administrator.');
      }
      // Read once: both answers come from the same resolution. A caller with
      // no session user holds nothing (fail closed).
      const caps =
        isAdmin || req.session.userId === undefined
          ? []
          : await permissionService.getUserCapabilities(req.session.userId, false, req.tenantId);
      const canWriteVariables = isAdmin || caps.includes(CAPABILITIES.SITE_VARIABLES_WRITE);
      const canWriteSchedule = isAdmin || caps.includes(SITE_SCHEDULE_CAPABILITY);
      // The dry run's CHR column: whole for a platform admin, redacted (and
      // refused under a template that names no tenant) for RECONCILE_READ,
      // and absent for everybody else — not an empty column, no field at all.
      const chr = isAdmin ? 'full' : caps.includes(CAPABILITIES.RECONCILE_READ) ? 'redacted' : undefined;

      const data = await importSites(req.tenantId, csv, {
        dryRun,
        allocate,
        canWriteVariables,
        canWriteSchedule,
        chr,
        updatedBy: req.session.userId ?? null,
      });
      res.json({ success: true, data });
    } catch (err) {
      if (err instanceof SiteImportFileError) {
        res.status(400).json({ success: false, error: err.message, errors: err.problems });
        return;
      }
      if (err instanceof SiteImportForbiddenError) {
        next(new AppError(403, err.message));
        return;
      }
      next(err);
    }
  },
};
