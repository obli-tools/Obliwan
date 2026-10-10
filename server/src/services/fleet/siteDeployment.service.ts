/**
 * ObliWAN — the DEPLOYMENT STATE of every site, for the account manager who
 * follows a rollout ("à préparer → préparé au banc → en ligne par le tunnel →
 * en anomalie") and exports it to Excel.
 *
 * ┌─ DERIVED, NEVER STORED ──────────────────────────────────────────────────┐
 * │ There is no `deployment_state` column and there must not be one. Every   │
 * │ fact below already has exactly one writer: the allocator               │
 * │ (`site_provisioning`), the concentrator job (`concentrator_state`), the │
 * │ bench API (`bench_provisionings`), the PPP presence service              │
 * │ (`ppp_sessions`), the permanent health check (`device_health_checks`),   │
 * │ the reachability verdict (`reachability_verdicts`), the identity guard   │
 * │ (`devices.status = 'quarantined'`) and the bench qualification          │
 * │ (`devices.qualified_at`, benchQualification.service.ts). A stored state │
 * │ would be a second account of those facts, free to disagree with them —  │
 * │ and the one that disagrees is the one somebody reads. It is recomputed  │
 * │ on every request.                                                        │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ ONE QUERY PER TENANT ───────────────────────────────────────────────────┐
 * │ `loadSiteFacts` is a single SQL statement (CTEs) returning one row per   │
 * │ site with everything the classifier needs, devices folded into a JSON    │
 * │ array. 400 sites cost one round trip, not 400 (the harness counts them). │
 * │ Nothing prunes `ppp_sessions`, so the statement never aggregates its     │
 * │ history: it reads the OPEN sessions (the partial unique index holds      │
 * │ exactly those) and the few latest sessions of each device and each      │
 * │ allocation, through indexes. Its cost follows the number of sites, not   │
 * │ how often they flapped since the day they were installed (the harness    │
 * │ reads the plan over a large history and refuses a sequential scan).      │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * THE STATES, IN PRECEDENCE ORDER — the first rule that matches wins
 * (`classifySite`). "Up now" below means: a PPP session of the site is open
 * and its concentrator is NOT degraded, or a device answered a fresh health
 * check.
 *
 *   1. anomaly / device_quarantined   a device of the site is quarantined: the
 *                                     box at its address is not the recorded
 *                                     one (identity guard).
 *   2. anomaly / chr_failed           the concentrator job could not create
 *                                     the site's L2TP account.
 *   3. anomaly / bench_failed         the LATEST bench preparation of the site
 *                                     reported 'failed' (a later retry that
 *                                     succeeded or is in progress clears it)
 *                                     and the site is not up now — a failed
 *                                     re-run does not turn a working site red.
 *   4. anomaly / router_down          a device that had answered the health
 *                                     check is now CONFIRMED down (retries
 *                                     exhausted — `healthDisplay` = 'down').
 *   5. anomaly / tunnel_down          the site's tunnel was up and has been
 *                                     down for more than PPP_DOWN_GRACE_MIN,
 *                                     and no device answers the health check.
 *      (4 and 5 report `concentrator_degraded` instead when the observer is
 *      blind — see rule 6.)
 *   6. anomaly / concentrator_degraded
 *                                     the site was seen online, the observer
 *                                     is BLIND and no device answers a fresh
 *                                     health check. Blind = the site's
 *                                     concentrator is degraded by the reachability rule's own
 *                                     rule (`concentratorDegradation`), or the
 *                                     health check suppressed a device of the
 *                                     site for that reason (display
 *                                     'suppressed'). See the box below.
 *   7. online / tunnel_up             a PPP session of the site is open.
 *   8. online / health_ok             no session, but a device answers the
 *                                     health check (a device not behind the
 *                                     concentrator, for one).
 *   9. online / reconnecting          the tunnel dropped less than
 *                                     PPP_DOWN_GRACE_MIN ago.
 *  10. prepared / bench_applied[_chr_pending]
 *                                     the bench reported 'applied', and the box
 *                                     has not been seen at its site since —
 *                                     however long ago: a box in shipping is
 *                                     not an anomaly (box below).
 *  11. ready / chr_provisioned | chr_adopted | bench_compiled
 *                                     addresses allocated and the CHR account
 *                                     exists (created, or adopted from the CHR
 *                                     as it was); not yet prepared.
 *  12. allocated_pending_chr / chr_pending | bench_compiled
 *                                     addresses allocated, CHR account not yet
 *                                     created.
 *  13. not_applicable / concentrator_site
 *                                     no allocation, no CPE, and the site hosts
 *                                     a concentrator: nothing to deploy there.
 *  14. to_allocate / no_allocation    no allocation yet.
 *
 * ┌─ A DEGRADED CONCENTRATOR MAKES THE OBSERVER BLIND, NOT THE SITES DOWN ───┐
 * │ When presence cannot read the CHR's /ppp/active it leaves every session  │
 * │ it recorded OPEN, on purpose ("we do not know that they ended"), and the │
 * │ health check skips every device behind the CHR (`parent_degraded`). Read │
 * │ naively, those open rows say "online" for every site of the CHR at once. │
 * │ They are a memory, not a fact. So the concentrator is read here exactly  │
 * │ as reachability reads it (`parentConcentratorDegraded` in                │
 * │ reachability.service.ts: a FRESH API health row confirmed down, or a     │
 * │ CONCENTRATOR_DEGRADED verdict younger than                               │
 * │ CONCENTRATOR_DEGRADED_TTL_SEC) — on the CHR's own                        │
 * │ rows, the only place reachability writes that verdict: a child's         │
 * │ suppressed verdict is never stored. A site already seen online then      │
 * │ reads "presence                                                          │
 * │ unknown" (rule 6), not "online" and not "down". A site still waiting for │
 * │ its installation keeps its state: the outage does not change it.        │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ A BOX IS SEEN AT ITS SITE WHEN IT IS QUALIFIED ─────────────────────────┐
 * │ A box prepared at the bench may dial its tunnel from the bench before it │
 * │ is unplugged and shipped, for a day to three weeks. Counted as "seen     │
 * │ online", that session would turn every box in shipping into "was        │
 * │ online, now down" — red, for weeks, on a site where nothing is wrong.   │
 * │ So after a preparation, nothing the box did counts as it being at its   │
 * │ site — no session, no health answer — until it is QUALIFIED for that    │
 * │ preparation: its tunnel held without a break for an hour right after   │
 * │ the preparation, or fifteen minutes later (the operator rule of         │
 * │ 2026-10-04; benchQualification.service.ts decides it and is the one     │
 * │ writer of `devices.qualified_at`). Once qualified, everything after the │
 * │ bench report counts. It is the SAME rule that gates the box's alerts in │
 * │ the health check: a box in shipping is neither announced down there nor │
 * │ shown down here. A tunnel that is up RIGHT NOW is online whatever its   │
 * │ age (rule 7): that is a fact, not an inference. There is no "prepared   │
 * │ long ago and never seen" anomaly: a box shipped overseas is not late,   │
 * │ and a time-based alert about it is the noise the rule exists to remove. │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * Every state carries the instant it is based on (`since`) and a short French
 * sentence (`detail`) — the export's text. The page localises from `reason`.
 *
 * What never leaves this module: the PPP password (the vault column is not
 * selected), the concentrator's error text and the bench's free-text report
 * (both may quote what a router printed; the sentence says what happened, not
 * what the box said), any other tenant's row. Every table is filtered on the
 * session's tenant; `ppp_sessions` has no tenant, so it is reached only through
 * this tenant's devices or this tenant's allocation (its login, on its own
 * concentrator — logins are unique across the installation, migration 036).
 * The concentrator itself may belong to the master tenant: it is reached only
 * through this tenant's own foreign keys (`site_provisioning.concentrator_id`,
 * `devices.concentrator_id`), and only "degraded or not, since when" comes
 * out of its rows.
 */

import {
  healthDisplay,
  healthFreshnessMs,
  type HealthDisplay,
  type DeviceHealthState,
  type HealthSkipReason,
} from '@obliwan/shared';
import { db } from '../../db';
import { isGodView, tenantIdsInScope, tenantNames } from '../../utils/globalView';
import { logsConfig } from '../logs/config';
import { buildXlsx, isoDateIn, type XlsxColumn, type XlsxValue } from './xlsx';

// ============================================================================
// Vocabulary and constants
// ============================================================================

export const SITE_DEPLOYMENT_STATES = [
  'anomaly',
  'online',
  'prepared',
  'ready',
  'allocated_pending_chr',
  'to_allocate',
  'not_applicable',
] as const;
export type SiteDeploymentState = (typeof SITE_DEPLOYMENT_STATES)[number];

export const SITE_DEPLOYMENT_REASONS = [
  'device_quarantined',
  'chr_failed',
  'bench_failed',
  'router_down',
  'tunnel_down',
  'concentrator_degraded',
  'tunnel_up',
  'health_ok',
  'reconnecting',
  'bench_applied',
  'bench_applied_chr_pending',
  'chr_provisioned',
  'chr_adopted',
  'bench_compiled',
  'chr_pending',
  'concentrator_site',
  'no_allocation',
] as const;
export type SiteDeploymentReason = (typeof SITE_DEPLOYMENT_REASONS)[number];

/** A tunnel down for less than this is a reconnection, not an outage. */
export const PPP_DOWN_GRACE_MIN = 15;

/** The French label of each state: the export's "État" column. */
export const STATE_LABEL_FR: Record<SiteDeploymentState, string> = {
  anomaly: 'En anomalie',
  online: 'En ligne',
  prepared: 'Préparé au banc',
  ready: 'À préparer',
  allocated_pending_chr: 'En attente du concentrateur',
  to_allocate: 'Adresses à attribuer',
  not_applicable: 'Non concerné',
};

// ============================================================================
// Facts, as the one query returns them
// ============================================================================

interface DeviceFacts {
  id: number;
  name: string;
  model: string | null;
  serial: string | null;
  status: string;
  pppUsername: string | null;
  tunnelIp: string | null;
  concentratorId: number | null;
  health: {
    state: DeviceHealthState;
    consecutiveFailures: number;
    skipReason: HealthSkipReason | null;
    lastCheckAt: Date | null;
    intervalSec: number | null;
    lastOkAt: Date | null;
    downSince: Date | null;
  } | null;
}

/** A concentrator the site depends on: what reachability reads to call it degraded. */
export interface ConcentratorFacts {
  id: number;
  /** Its permanent health check row (migration 043), or null. */
  health: {
    state: DeviceHealthState;
    channel: string | null;
    lastCheckAt: Date | null;
    intervalSec: number | null;
    downSince: Date | null;
  } | null;
  /** Its latest reachability verdict, or null. */
  verdict: string | null;
  verdictAt: Date | null;
}

export interface SiteFacts {
  siteId: number;
  code: string;
  name: string;
  country: string | null;
  address: string | null;
  contact: string | null;
  createdAt: Date;
  hostsConcentrator: boolean;
  allocation: {
    pppLogin: string;
    tunnelIp: string;
    lanSubnet: string | null;
    concentratorState: 'pending' | 'provisioned' | 'failed';
    source: 'allocated' | 'adopted_chr' | null;
    allocatedAt: Date;
    updatedAt: Date;
  } | null;
  sessions: {
    /** Earliest start among the site's OPEN sessions; null = none open. */
    openSince: Date | null;
    lastStartedAt: Date | null;
    lastEndedAt: Date | null;
  };
  /** The latest bench row of the site (by compile instant), whatever its outcome. */
  latestBench: {
    outcome: 'compiled' | 'applied' | 'failed';
    compiledAt: Date;
    outcomeAt: Date | null;
    deviceId: number;
    station: string | null;
  } | null;
  /** The latest bench row that reported 'applied'. */
  appliedBench: {
    outcomeAt: Date;
    deviceId: number;
    station: string | null;
    /** When that device qualified for THIS preparation (migration 068), or
     *  null: until then nothing it did counts as it being at its site. */
    qualifiedAt: Date | null;
    /** The device has a PPP account on a concentrator, i.e. a presence that
     *  can qualify it. Without one the rule does not hold it — as in
     *  benchQualification.service.ts, which would otherwise silence a box
     *  nothing could ever qualify. */
    qualificationApplies: boolean;
  } | null;
  /** CPE only: a concentrator filed under the site is not what is deployed. */
  devices: DeviceFacts[];
  /** The concentrators the site depends on: its allocation's, its devices'. */
  concentrators: ConcentratorFacts[];
}

export interface SiteDeploymentFilters {
  /** Case-insensitive substring of the name, code, address or contact — the
   *  same four fields, and the same comparison, as the sites page
   *  (`matchesSearch`). */
  search?: string;
  /** Keep only these states. Empty or absent = all. */
  states?: SiteDeploymentState[];
  /** Team scope (migration 084): keep only these sites. Absent/null = all. */
  siteIds?: ReadonlySet<number> | null;
}

function toDate(v: unknown): Date | null {
  if (v === null || v === undefined) return null;
  const d = v instanceof Date ? v : new Date(String(v));
  return Number.isNaN(d.getTime()) ? null : d;
}

/**
 * The page's search, verbatim (client/src/pages/SitesPage.tsx, `searched`):
 * the trimmed needle, lower-cased by JavaScript, as a substring of any
 * non-empty field among name, code, address and contact. Done HERE rather than
 * with ILIKE because the file must hold what the screen shows, and ILIKE's
 * case folding depends on the database's ctype — under `C` it does not fold
 * "É" to "é", while String.prototype.toLowerCase does, in the browser and here
 * alike. The four columns are in the one query anyway; filtering after it
 * costs nothing at a few hundred sites.
 */
export function matchesSearch(
  f: Pick<SiteFacts, 'name' | 'code' | 'address' | 'contact'>,
  search: string | undefined,
): boolean {
  const needle = (search ?? '').trim().toLowerCase();
  if (!needle) return true;
  return [f.name, f.code, f.address, f.contact]
    .filter(Boolean)
    .some((v) => String(v).toLowerCase().includes(needle));
}

/**
 * The single statement. Named bindings only; no `?` and no `::` anywhere in
 * the text (knex reads both as binding syntax — see migration 032).
 *
 * PPP logins are matched EXACTLY. `ppp_sessions.ppp_username` is the name the
 * CHR reports, and the CHR's secret carries the allocation's login verbatim:
 * the concentrator job creates it as `name=<site_provisioning.ppp_username>`,
 * and an adoption records the CHR's `secret.name` as the login. Presence binds
 * a session to its device by the same exact equality (`deviceForUsername`).
 * A case-insensitive join here would also defeat the (ppp_username,
 * started_at) index, which is what keeps the history read bounded.
 *
 * Exported for the harness, which reads its plan (`EXPLAIN`); its only
 * binding is `:tenantId`.
 */
export const SITE_FACTS_SQL = `
WITH s AS (
  SELECT st.id, st.code, st.name, st.country, st.address, st.contact, st.created_at,
         EXISTS (
           SELECT 1 FROM devices c
            WHERE c.site_id = st.id AND c.tenant_id = :tenantId AND c.role = 'concentrator'
         ) AS hosts_concentrator
    FROM sites st
   WHERE st.tenant_id = :tenantId
),
dev AS (
  SELECT d.id, d.site_id, d.name, d.model, d.serial, d.status, d.ppp_username,
         d.concentrator_id, host(d.tunnel_ip) AS tunnel_ip
    FROM devices d
    JOIN s ON s.id = d.site_id
   WHERE d.tenant_id = :tenantId AND d.role <> 'concentrator'
),
sp AS (
  SELECT p.site_id, p.ppp_username, host(p.tunnel_ip) AS tunnel_ip,
         CAST(p.lan_subnet AS text) AS lan_subnet, p.concentrator_id,
         p.concentrator_state, p.source, p.allocated_at, p.updated_at
    FROM site_provisioning p
    JOIN s ON s.id = p.site_id
   WHERE p.tenant_id = :tenantId
),
sess_open AS (
  -- The OPEN sessions of the installation: exactly the rows of the partial
  -- unique index ppp_sessions_open_uniq, as many as there are live tunnels.
  SELECT ps.device_id, ps.concentrator_id, ps.ppp_username, ps.started_at
    FROM ppp_sessions ps
   WHERE ps.ended_at IS NULL
),
open_agg AS (
  SELECT o.site_id, MIN(o.started_at) AS open_since
    FROM (
      SELECT dev.site_id, so.started_at
        FROM sess_open so
        JOIN dev ON dev.id = so.device_id
      UNION ALL
      SELECT sp.site_id, so.started_at
        FROM sess_open so
        JOIN sp ON so.concentrator_id = sp.concentrator_id
               AND so.ppp_username = sp.ppp_username
    ) o
   GROUP BY o.site_id
),
recent AS (
  -- The 4 latest sessions of each device and of each allocation, by index.
  -- Presence opens a session for a (concentrator, login) only when none is
  -- open (applySessionUp; ppp_sessions_open_uniq), so one login's sessions
  -- follow one another and its latest end belongs to its latest start; the
  -- extra rows cover a device whose sessions span more than one login.
  SELECT dev.site_id, r.started_at, r.ended_at
    FROM dev
    CROSS JOIN LATERAL (
      SELECT ps.started_at, ps.ended_at
        FROM ppp_sessions ps
       WHERE ps.device_id = dev.id
       ORDER BY ps.started_at DESC
       LIMIT 4
    ) r
  UNION ALL
  SELECT sp.site_id, r.started_at, r.ended_at
    FROM sp
    CROSS JOIN LATERAL (
      SELECT ps.started_at, ps.ended_at
        FROM ppp_sessions ps
       WHERE ps.ppp_username = sp.ppp_username
         AND ps.concentrator_id = sp.concentrator_id
       ORDER BY ps.started_at DESC
       LIMIT 4
    ) r
),
recent_agg AS (
  SELECT site_id, MAX(started_at) AS last_started_at, MAX(ended_at) AS last_ended_at
    FROM recent
   GROUP BY site_id
),
conc_link AS (
  SELECT sp.site_id, sp.concentrator_id AS cid FROM sp WHERE sp.concentrator_id IS NOT NULL
  UNION
  SELECT dev.site_id, dev.concentrator_id AS cid FROM dev WHERE dev.concentrator_id IS NOT NULL
),
conc AS (
  -- Each concentrator read ONCE, however many sites hang off it.
  SELECT c.cid, h.device_id IS NOT NULL AS h_present, h.state AS h_state,
         h.channel AS h_channel, h.last_check_at AS h_last_check_at,
         h.interval_sec AS h_interval, h.down_since AS h_down_since,
         v.verdict, v.ts AS verdict_ts
    FROM (SELECT DISTINCT cid FROM conc_link) c
    LEFT JOIN device_health_checks h ON h.device_id = c.cid
    LEFT JOIN LATERAL (
      SELECT rv.verdict, rv.ts
        FROM reachability_verdicts rv
       WHERE rv.device_id = c.cid
       ORDER BY rv.ts DESC
       LIMIT 1
    ) v ON true
),
conc_agg AS (
  SELECT cl.site_id,
         json_agg(json_build_object(
           'id', conc.cid, 'hPresent', conc.h_present, 'hState', conc.h_state,
           'hChannel', conc.h_channel, 'hLastCheckAt', conc.h_last_check_at,
           'hInterval', conc.h_interval, 'hDownSince', conc.h_down_since,
           'verdict', conc.verdict, 'verdictAt', conc.verdict_ts
         ) ORDER BY conc.cid) AS concentrators
    FROM conc_link cl
    JOIN conc ON conc.cid = cl.cid
   GROUP BY cl.site_id
),
bench_latest AS (
  SELECT DISTINCT ON (b.site_id)
         b.site_id, b.outcome, b.compiled_at, b.outcome_at, b.device_id, bs.name AS station
    FROM bench_provisionings b
    JOIN s ON s.id = b.site_id
    LEFT JOIN bench_stations bs ON bs.id = b.station_id
   WHERE b.tenant_id = :tenantId
   ORDER BY b.site_id, b.compiled_at DESC, b.id DESC
),
bench_applied AS (
  -- The qualification counts only for the preparation it was earned after
  -- (devices.qualified_provisioning_id, migration 068), and only a device
  -- with a PPP account on a concentrator can earn one.
  SELECT DISTINCT ON (b.site_id)
         b.site_id, b.outcome_at, b.device_id, bs.name AS station,
         CASE WHEN qd.qualified_provisioning_id = b.id THEN qd.qualified_at END AS qualified_at,
         (qd.concentrator_id IS NOT NULL AND COALESCE(qd.ppp_username, '') <> '') AS qualification_applies
    FROM bench_provisionings b
    JOIN s ON s.id = b.site_id
    LEFT JOIN bench_stations bs ON bs.id = b.station_id
    LEFT JOIN devices qd ON qd.id = b.device_id AND qd.tenant_id = :tenantId
   WHERE b.tenant_id = :tenantId AND b.outcome = 'applied'
   ORDER BY b.site_id, b.outcome_at DESC, b.id DESC
),
dev_agg AS (
  SELECT dev.site_id,
         json_agg(json_build_object(
           'id', dev.id, 'name', dev.name, 'model', dev.model, 'serial', dev.serial,
           'status', dev.status, 'pppUsername', dev.ppp_username, 'tunnelIp', dev.tunnel_ip,
           'concentratorId', dev.concentrator_id,
           'hPresent', h.device_id IS NOT NULL, 'hState', h.state,
           'hFailures', h.consecutive_failures, 'hSkip', h.skip_reason,
           'hLastCheckAt', h.last_check_at, 'hInterval', h.interval_sec,
           'hLastOkAt', h.last_ok_at, 'hDownSince', h.down_since
         ) ORDER BY dev.id) AS devices
    FROM dev
    LEFT JOIN device_health_checks h ON h.device_id = dev.id
   GROUP BY dev.site_id
)
SELECT s.id AS site_id, s.code, s.name, s.country, s.address, s.contact, s.created_at,
       s.hosts_concentrator,
       sp.ppp_username AS a_login, sp.tunnel_ip AS a_tunnel_ip, sp.lan_subnet AS a_lan,
       sp.concentrator_state AS a_state, sp.source AS a_source,
       sp.allocated_at AS a_allocated_at, sp.updated_at AS a_updated_at,
       oa.open_since, ra.last_started_at, ra.last_ended_at,
       bl.outcome AS bl_outcome, bl.compiled_at AS bl_compiled_at, bl.outcome_at AS bl_outcome_at,
       bl.device_id AS bl_device_id, bl.station AS bl_station,
       ba.outcome_at AS ba_outcome_at, ba.device_id AS ba_device_id, ba.station AS ba_station,
       ba.qualified_at AS ba_qualified_at, ba.qualification_applies AS ba_qualification_applies,
       da.devices, ca.concentrators
  FROM s
  LEFT JOIN sp ON sp.site_id = s.id
  LEFT JOIN open_agg oa ON oa.site_id = s.id
  LEFT JOIN recent_agg ra ON ra.site_id = s.id
  LEFT JOIN bench_latest bl ON bl.site_id = s.id
  LEFT JOIN bench_applied ba ON ba.site_id = s.id
  LEFT JOIN dev_agg da ON da.site_id = s.id
  LEFT JOIN conc_agg ca ON ca.site_id = s.id
`;

interface FactsRow {
  site_id: number;
  code: string;
  name: string;
  country: string | null;
  address: string | null;
  contact: string | null;
  created_at: Date;
  hosts_concentrator: boolean;
  a_login: string | null;
  a_tunnel_ip: string | null;
  a_lan: string | null;
  a_state: 'pending' | 'provisioned' | 'failed' | null;
  a_source: 'allocated' | 'adopted_chr' | null;
  a_allocated_at: Date | null;
  a_updated_at: Date | null;
  open_since: Date | null;
  last_started_at: Date | null;
  last_ended_at: Date | null;
  bl_outcome: 'compiled' | 'applied' | 'failed' | null;
  bl_compiled_at: Date | null;
  bl_outcome_at: Date | null;
  bl_device_id: number | null;
  bl_station: string | null;
  ba_outcome_at: Date | null;
  ba_device_id: number | null;
  ba_station: string | null;
  ba_qualified_at: Date | null;
  ba_qualification_applies: boolean | null;
  devices: Array<Record<string, unknown>> | null;
  concentrators: Array<Record<string, unknown>> | null;
}

const str = (v: unknown): string | null => (typeof v === 'string' ? v : null);
const numOrNull = (v: unknown): number | null => (v === null || v === undefined ? null : Number(v));

function toDeviceFacts(raw: Record<string, unknown>): DeviceFacts {
  return {
    id: Number(raw.id),
    name: String(raw.name ?? ''),
    model: str(raw.model),
    serial: str(raw.serial),
    status: String(raw.status ?? ''),
    pppUsername: str(raw.pppUsername),
    tunnelIp: str(raw.tunnelIp),
    concentratorId: numOrNull(raw.concentratorId),
    health: raw.hPresent === true
      ? {
        state: (str(raw.hState) ?? 'unknown') as DeviceHealthState,
        consecutiveFailures: Number(raw.hFailures ?? 0),
        skipReason: str(raw.hSkip) as HealthSkipReason | null,
        lastCheckAt: toDate(raw.hLastCheckAt),
        intervalSec: numOrNull(raw.hInterval),
        lastOkAt: toDate(raw.hLastOkAt),
        downSince: toDate(raw.hDownSince),
      }
      : null,
  };
}

function toConcentratorFacts(raw: Record<string, unknown>): ConcentratorFacts {
  return {
    id: Number(raw.id),
    health: raw.hPresent === true
      ? {
        state: (str(raw.hState) ?? 'unknown') as DeviceHealthState,
        channel: str(raw.hChannel),
        lastCheckAt: toDate(raw.hLastCheckAt),
        intervalSec: numOrNull(raw.hInterval),
        downSince: toDate(raw.hDownSince),
      }
      : null,
    verdict: str(raw.verdict),
    verdictAt: toDate(raw.verdictAt),
  };
}

/** Every site of the tenant, with its facts. ONE query. */
export async function loadSiteFacts(tenantId: number): Promise<SiteFacts[]> {
  const result = (await db.raw(SITE_FACTS_SQL, { tenantId })) as { rows: FactsRow[] };
  return result.rows.map((r) => ({
    siteId: Number(r.site_id),
    code: r.code,
    name: r.name,
    country: r.country,
    address: r.address,
    contact: r.contact,
    createdAt: toDate(r.created_at) ?? new Date(0),
    hostsConcentrator: r.hosts_concentrator === true,
    allocation: r.a_login !== null && r.a_tunnel_ip !== null && r.a_state !== null
      ? {
        pppLogin: r.a_login,
        tunnelIp: r.a_tunnel_ip,
        lanSubnet: r.a_lan,
        concentratorState: r.a_state,
        source: r.a_source,
        allocatedAt: toDate(r.a_allocated_at) ?? new Date(0),
        updatedAt: toDate(r.a_updated_at) ?? new Date(0),
      }
      : null,
    sessions: {
      openSince: toDate(r.open_since),
      lastStartedAt: toDate(r.last_started_at),
      lastEndedAt: toDate(r.last_ended_at),
    },
    latestBench: r.bl_outcome !== null && r.bl_compiled_at !== null && r.bl_device_id !== null
      ? {
        outcome: r.bl_outcome,
        compiledAt: toDate(r.bl_compiled_at) ?? new Date(0),
        outcomeAt: toDate(r.bl_outcome_at),
        deviceId: Number(r.bl_device_id),
        station: r.bl_station,
      }
      : null,
    appliedBench: r.ba_outcome_at !== null && r.ba_device_id !== null
      ? {
        outcomeAt: toDate(r.ba_outcome_at) ?? new Date(0),
        deviceId: Number(r.ba_device_id),
        station: r.ba_station,
        qualifiedAt: toDate(r.ba_qualified_at),
        qualificationApplies: r.ba_qualification_applies === true,
      }
      : null,
    devices: (r.devices ?? []).map(toDeviceFacts),
    concentrators: (r.concentrators ?? []).map(toConcentratorFacts),
  }));
}

// ============================================================================
// Classification — pure
// ============================================================================

export interface SiteDeploymentVerdict {
  state: SiteDeploymentState;
  reason: SiteDeploymentReason;
  /** The instant the state is based on (see each rule). */
  since: Date | null;
  /** The device the sentence names, when it names one. */
  subjectDeviceId: number | null;
}

function display(d: DeviceFacts, nowMs: number): HealthDisplay {
  return healthDisplay(
    d.health
      ? {
        state: d.health.state,
        consecutiveFailures: d.health.consecutiveFailures,
        skipReason: d.health.skipReason,
        lastCheckAt: d.health.lastCheckAt ? d.health.lastCheckAt.toISOString() : null,
        intervalSec: d.health.intervalSec,
      }
      : null,
    nowMs,
    d.status === 'disabled',
  );
}

function minDate(dates: Array<Date | null>): Date | null {
  let best: Date | null = null;
  for (const d of dates) if (d && (!best || d < best)) best = d;
  return best;
}

function maxDate(dates: Array<Date | null>): Date | null {
  let best: Date | null = null;
  for (const d of dates) if (d && (!best || d > best)) best = d;
  return best;
}

/**
 * Is this concentrator degraded, and since when? The reachability rule, applied to the
 * facts the one query already read: the mirror of `parentConcentratorDegraded`
 * in reachability.service.ts (which reads them one device at a time, and which
 * the health check uses to suppress the devices behind it). The two must
 * change together.
 *
 *   1. its permanent health check is an API read (`routeros_api`), FRESH
 *      (`healthFreshnessMs`) and confirms it down — since `down_since`;
 *   2. otherwise its latest verdict is CONCENTRATOR_DEGRADED and younger than
 *      `ttlSec` (CONCENTRATOR_DEGRADED_TTL_SEC) — since that verdict.
 */
export function concentratorDegradation(
  c: ConcentratorFacts,
  nowMs: number,
  ttlSec: number,
): { degraded: boolean; since: Date | null } {
  const h = c.health;
  if (
    h &&
    h.channel === 'routeros_api' &&
    h.lastCheckAt !== null &&
    h.intervalSec &&
    nowMs - h.lastCheckAt.getTime() <= healthFreshnessMs(h.intervalSec) &&
    h.state === 'down'
  ) {
    return { degraded: true, since: h.downSince ?? h.lastCheckAt };
  }
  if (c.verdict === 'CONCENTRATOR_DEGRADED' && c.verdictAt && (nowMs - c.verdictAt.getTime()) / 1000 <= ttlSec) {
    return { degraded: true, since: c.verdictAt };
  }
  return { degraded: false, since: null };
}

export interface ClassifyOptions {
  /** The reachability rule's bound on a CONCENTRATOR_DEGRADED verdict, in seconds. */
  concentratorDegradedTtlSec?: number;
}

/** The precedence of the header, rule by rule. Pure: the clock is a parameter. */
export function classifySite(f: SiteFacts, nowMs: number, options: ClassifyOptions = {}): SiteDeploymentVerdict {
  const ttlSec = options.concentratorDegradedTtlSec ?? logsConfig.concentratorDegradedTtlSec;
  const verdict = (
    state: SiteDeploymentState,
    reason: SiteDeploymentReason,
    since: Date | null,
    subjectDeviceId: number | null = null,
  ): SiteDeploymentVerdict => ({ state, reason, since, subjectDeviceId });

  // 1. Identity. NO instant, on purpose: nothing stores when a device was
  //    quarantined. The guard writes the status together with `updated_at`
  //    (deviceBinding.service.ts), but every PPP session-up rewrites
  //    `updated_at` afterwards (pppPresence `applySessionUp`), so that column
  //    would date the last reconnection, not the quarantine. An empty
  //    "Depuis" is honest; a wrong one is believed.
  const quarantined = f.devices.find((d) => d.status === 'quarantined');
  if (quarantined) return verdict('anomaly', 'device_quarantined', null, quarantined.id);

  // 2. The concentrator refused the account. recordConcentratorOutcome stamps
  //    updated_at when it writes the state.
  if (f.allocation?.concentratorState === 'failed') {
    return verdict('anomaly', 'chr_failed', f.allocation.updatedAt);
  }

  // Presence. After a preparation, nothing says the box is at its site until
  // it is qualified for that preparation; from then on, what happened after
  // the bench report does (header box).
  const benchHeld =
    f.appliedBench !== null && f.appliedBench.qualificationApplies && f.appliedBench.qualifiedAt === null;
  const floorMs = f.appliedBench ? f.appliedBench.outcomeAt.getTime() : null;
  const afterFloor = (d: Date | null): boolean =>
    !benchHeld && d !== null && (floorMs === null || d.getTime() > floorMs);

  const tunnelOpen = f.sessions.openSince !== null;
  const healthOk = f.devices.filter((d) => display(d, nowMs) === 'ok');
  // A qualification IS a session after the report that held — even one that
  // opened at the bench just before the report came in.
  const sessionEvidence = (f.appliedBench?.qualifiedAt ?? null) !== null || afterFloor(f.sessions.lastStartedAt);
  const healthEvidence = f.devices.some((d) => afterFloor(d.health?.lastOkAt ?? null));
  const graceMs = PPP_DOWN_GRACE_MIN * 60_000;

  // Is the observer blind? The site's concentrators read by the reachability rule, or —
  // the health check's own word for the same thing — a device of the site
  // suppressed because its concentrator is degraded (header box). The
  // suppressed reading carries no instant of its own.
  const degradedSince = f.concentrators
    .map((c) => concentratorDegradation(c, nowMs, ttlSec))
    .filter((d) => d.degraded)
    .map((d) => d.since);
  const blind =
    degradedSince.length > 0 || f.devices.some((d) => display(d, nowMs) === 'suppressed');
  const blindSince = minDate(degradedSince);

  // Up now: an open tunnel the concentrator can still vouch for, or a fresh
  // direct answer from a device.
  const upNow = (tunnelOpen && !blind) || healthOk.length > 0;

  // 3. The latest preparation failed — and the site is not working anyway. A
  //    failed RE-RUN (a replacement box, a retry) on a site whose tunnel is up
  //    does not make that site an anomaly: the box in service is fine. If the
  //    site later goes down, this rule wins again over 4 and 5.
  if (f.latestBench?.outcome === 'failed' && !upNow) {
    return verdict('anomaly', 'bench_failed', f.latestBench.outcomeAt, f.latestBench.deviceId);
  }

  // 4. A device that answered (after the bench window) is now confirmed down.
  const routerDown = f.devices.filter(
    (d) => display(d, nowMs) === 'down' && afterFloor(d.health?.lastOkAt ?? null),
  );
  if (routerDown.length > 0) {
    return verdict(
      'anomaly',
      blind ? 'concentrator_degraded' : 'router_down',
      minDate(routerDown.map((d) => d.health?.downSince ?? null)),
      routerDown[0].id,
    );
  }

  // 5. The tunnel was up and has been down past the grace period. With no
  //    session open, every session has ended, so the latest end is the moment
  //    the tunnel went down.
  const lastEnd = f.sessions.lastEndedAt;
  if (
    !tunnelOpen &&
    healthOk.length === 0 &&
    sessionEvidence &&
    lastEnd !== null &&
    nowMs - lastEnd.getTime() > graceMs
  ) {
    return verdict('anomaly', blind ? 'concentrator_degraded' : 'tunnel_down', lastEnd);
  }

  // 6. Blind, on a site already seen online: an open row is a memory, not a
  //    fact, and a tunnel that came back would not be recorded. Neither
  //    "online" nor "down" can be said. A fresh direct health answer still
  //    wins (rule 8): that one is a measurement.
  if (blind && healthOk.length === 0 && (tunnelOpen || sessionEvidence || healthEvidence)) {
    return verdict('anomaly', 'concentrator_degraded', blindSince);
  }

  // 7–9. Online.
  if (tunnelOpen) return verdict('online', 'tunnel_up', f.sessions.openSince);
  if (healthOk.length > 0) {
    // There is no "up since" in device_health_checks: the instant is the
    // latest successful check, and the sentence says so.
    return verdict('online', 'health_ok', maxDate(healthOk.map((d) => d.health?.lastOkAt ?? null)), healthOk[0].id);
  }
  if (sessionEvidence && lastEnd !== null && nowMs - lastEnd.getTime() <= graceMs) {
    return verdict('online', 'reconnecting', f.sessions.lastStartedAt);
  }

  // 10. Prepared: in shipping or waiting to be installed, however long ago
  //     (header box: no time-based "never installed" anomaly).
  if (f.appliedBench) {
    const chrPending =
      f.allocation !== null &&
      f.allocation.concentratorState === 'pending' &&
      f.allocation.source !== 'adopted_chr';
    return verdict(
      'prepared',
      chrPending ? 'bench_applied_chr_pending' : 'bench_applied',
      f.appliedBench.outcomeAt,
      f.appliedBench.deviceId,
    );
  }

  const compiling = f.latestBench?.outcome === 'compiled' ? f.latestBench : null;

  // 11–12. Allocated.
  if (f.allocation) {
    const adopted = f.allocation.source === 'adopted_chr';
    if (f.allocation.concentratorState === 'provisioned' || adopted) {
      if (compiling) return verdict('ready', 'bench_compiled', compiling.compiledAt, compiling.deviceId);
      return adopted
        ? verdict('ready', 'chr_adopted', f.allocation.allocatedAt)
        : verdict('ready', 'chr_provisioned', f.allocation.updatedAt);
    }
    if (compiling) {
      return verdict('allocated_pending_chr', 'bench_compiled', compiling.compiledAt, compiling.deviceId);
    }
    return verdict('allocated_pending_chr', 'chr_pending', f.allocation.allocatedAt);
  }

  // 13. A concentrator's own site.
  if (f.hostsConcentrator && f.devices.length === 0) {
    return verdict('not_applicable', 'concentrator_site', f.createdAt);
  }

  // 14.
  return verdict('to_allocate', 'no_allocation', f.createdAt);
}

// ============================================================================
// The row: verdict + what the page and the export show
// ============================================================================

export interface SiteDeploymentDevice {
  id: number;
  name: string;
  model: string | null;
  serial: string | null;
}

export interface SiteDeploymentRow {
  /** God view only: the owning tenant (utils/globalView.ts). */
  tenantId?: number;
  tenantName?: string | null;
  siteId: number;
  code: string;
  name: string;
  country: string | null;
  address: string | null;
  state: SiteDeploymentState;
  reason: SiteDeploymentReason;
  since: Date | null;
  /** French sentence: the export's "Détail". */
  detail: string;
  /** Interpolation values of the reason's sentence, for the page's t(). */
  detailParams: { device: string | null; station: string | null };
  pppLogin: string | null;
  tunnelIp: string | null;
  lanSubnet: string | null;
  allocationSource: 'allocated' | 'adopted_chr' | null;
  preparedAt: Date | null;
  preparedBy: string | null;
  onlineSince: Date | null;
  device: SiteDeploymentDevice | null;
}

/**
 * The device the row describes: the one the sentence names, else the one the
 * latest preparation was compiled for, else the one carrying the site's login,
 * else the oldest.
 */
function pickDevice(f: SiteFacts, subjectId: number | null): DeviceFacts | null {
  if (f.devices.length === 0) return null;
  const byId = (id: number | null | undefined) =>
    id === null || id === undefined ? undefined : f.devices.find((d) => d.id === id);
  const login = f.allocation?.pppLogin.toLowerCase() ?? null;
  return (
    byId(subjectId) ??
    byId(f.latestBench?.deviceId) ??
    (login ? f.devices.find((d) => d.pppUsername?.toLowerCase() === login) : undefined) ??
    f.devices[0]
  );
}

/** The French sentence of a reason. `station` and `device` are interpolated. */
export function detailFr(
  reason: SiteDeploymentReason,
  params: { device: string | null; station: string | null },
): string {
  const device = params.device ? ` « ${params.device} »` : '';
  const station = params.station ? ` (poste ${params.station})` : '';
  switch (reason) {
    case 'device_quarantined':
      return `Routeur${device} mis en quarantaine : il ne correspond plus à sa fiche`;
    case 'chr_failed':
      return 'La création du compte sur le concentrateur a échoué';
    case 'bench_failed':
      return `La préparation au banc a échoué${station}`;
    case 'router_down':
      return `Le routeur${device} ne répond plus`;
    case 'tunnel_down':
      return `Le tunnel est coupé depuis plus de ${PPP_DOWN_GRACE_MIN} min`;
    case 'concentrator_degraded':
      // Not "hors ligne": with the concentrator unreadable, nobody knows.
      return 'Concentrateur injoignable : impossible de vérifier si le site est en ligne';
    case 'tunnel_up':
      return 'Tunnel établi';
    case 'health_ok':
      return `Le routeur${device} répond aux vérifications (« Depuis » = dernière réponse)`;
    case 'reconnecting':
      return `Tunnel coupé il y a moins de ${PPP_DOWN_GRACE_MIN} min, reconnexion attendue`;
    case 'bench_applied':
      return `Préparé au banc${station}, en attente d’installation`;
    case 'bench_applied_chr_pending':
      return `Préparé au banc${station}, compte du concentrateur pas encore créé`;
    case 'chr_provisioned':
      return 'Adresses attribuées et compte du concentrateur créé : prêt pour le banc';
    case 'chr_adopted':
      return 'Compte repris du concentrateur existant : prêt pour le banc';
    case 'bench_compiled':
      return `Configuration générée au banc${station}, résultat attendu`;
    case 'chr_pending':
      return 'Adresses attribuées, compte du concentrateur en attente';
    case 'concentrator_site':
      return 'Site du concentrateur : rien à déployer';
    case 'no_allocation':
      return 'Aucune adresse attribuée';
  }
}

export function toDeploymentRow(f: SiteFacts, nowMs: number): SiteDeploymentRow {
  const v = classifySite(f, nowMs);
  const device = pickDevice(f, v.subjectDeviceId);
  const station =
    v.reason === 'bench_failed' || v.reason === 'bench_compiled'
      ? f.latestBench?.station ?? null
      : f.appliedBench?.station ?? null;
  const params = { device: device?.name ?? null, station };
  return {
    siteId: f.siteId,
    code: f.code,
    name: f.name,
    country: f.country,
    address: f.address,
    state: v.state,
    reason: v.reason,
    since: v.since,
    detail: detailFr(v.reason, params),
    detailParams: params,
    // The allocation is the plan; a site never allocated by ObliWAN (deployed
    // before the allocator existed) shows what its device carries instead.
    pppLogin: f.allocation?.pppLogin ?? device?.pppUsername ?? null,
    tunnelIp: f.allocation?.tunnelIp ?? device?.tunnelIp ?? null,
    lanSubnet: f.allocation?.lanSubnet ?? null,
    allocationSource: f.allocation?.source ?? null,
    preparedAt: f.appliedBench?.outcomeAt ?? null,
    preparedBy: f.appliedBench?.station ?? null,
    // An open row the concentrator can no longer vouch for is not "en ligne
    // depuis" anything (rule 6): the column stays empty rather than repeat it.
    onlineSince: v.reason === 'concentrator_degraded' ? null : f.sessions.openSince,
    device: device ? { id: device.id, name: device.name, model: device.model, serial: device.serial } : null,
  };
}

const collator = new Intl.Collator('fr', { sensitivity: 'base', numeric: true });

/** Every site of the tenant with its state, sorted as the sites page sorts. */
export async function listSiteDeployments(
  tenantId: number,
  filters: SiteDeploymentFilters = {},
  nowMs: number = Date.now(),
): Promise<SiteDeploymentRow[]> {
  // God view (a platform admin's GET on the master tenant): every tenant's
  // sites, read tenant by tenant through the same per-tenant SQL, each row
  // tagged with its tenant. Anyone else: this tenant's, exactly as before.
  const godView = isGodView(tenantId);
  const tenantIds = await tenantIdsInScope(tenantId);
  const names = godView ? await tenantNames(tenantIds) : new Map<number, string>();
  const keep = filters.states && filters.states.length > 0 ? new Set(filters.states) : null;
  const out: SiteDeploymentRow[] = [];
  for (const tid of tenantIds) {
    const facts = await loadSiteFacts(tid);
    for (const f of facts) {
      if (!matchesSearch(f, filters.search)) continue;
      if (filters.siteIds && !filters.siteIds.has(Number(f.siteId))) continue;
      const row = toDeploymentRow(f, nowMs);
      if (keep && !keep.has(row.state)) continue;
      out.push(godView ? { ...row, tenantId: tid, tenantName: names.get(tid) ?? null } : row);
    }
  }
  return out.sort((a, b) => collator.compare(a.name, b.name) || collator.compare(a.code, b.code));
}

/** The wire form: instants as ISO strings. */
export function toDeploymentDto(r: SiteDeploymentRow) {
  const iso = (d: Date | null) => (d ? d.toISOString() : null);
  return {
    ...(r.tenantId !== undefined ? { tenantId: r.tenantId, tenantName: r.tenantName ?? null } : {}),
    siteId: r.siteId,
    code: r.code,
    name: r.name,
    state: r.state,
    reason: r.reason,
    since: iso(r.since),
    detail: r.detail,
    detailParams: r.detailParams,
    pppLogin: r.pppLogin,
    tunnelIp: r.tunnelIp,
    lanSubnet: r.lanSubnet,
    allocationSource: r.allocationSource,
    preparedAt: iso(r.preparedAt),
    preparedBy: r.preparedBy,
    onlineSince: iso(r.onlineSince),
    device: r.device,
  };
}

// ============================================================================
// Excel export
// ============================================================================

export const EXPORT_COLUMNS: XlsxColumn[] = [
  { header: 'Code', width: 12, type: 'text' },
  { header: 'Site', width: 32, type: 'text' },
  { header: 'Pays', width: 6, type: 'text' },
  { header: 'Adresse', width: 40, type: 'text' },
  { header: 'État', width: 26, type: 'text' },
  { header: 'Depuis', width: 17, type: 'date' },
  { header: 'Détail', width: 62, type: 'text' },
  { header: 'Login PPP', width: 36, type: 'text' },
  { header: 'IP tunnel', width: 15, type: 'text' },
  { header: 'LAN', width: 18, type: 'text' },
  { header: 'Préparé le', width: 17, type: 'date' },
  { header: 'Poste de préparation', width: 22, type: 'text' },
  { header: 'En ligne depuis', width: 17, type: 'date' },
  { header: 'Routeur (modèle)', width: 20, type: 'text' },
  { header: 'N° de série', width: 18, type: 'text' },
];

function exportRow(r: SiteDeploymentRow): XlsxValue[] {
  return [
    r.code,
    r.name,
    r.country,
    r.address,
    STATE_LABEL_FR[r.state],
    r.since,
    r.detail,
    r.pppLogin,
    r.tunnelIp,
    r.lanSubnet,
    r.preparedAt,
    r.preparedBy,
    r.onlineSince,
    r.device?.model ?? null,
    r.device?.serial ?? null,
  ];
}

/** A tenant slug as a file name fragment: [a-z0-9-] only, never empty. */
function fileSlug(raw: string | null | undefined): string {
  const slug = (raw ?? '').toLowerCase().replace(/[^a-z0-9-]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 48);
  return slug || 'tenant';
}

export const DEFAULT_EXPORT_TIME_ZONE = 'Europe/Paris';

/**
 * The .xlsx of the filtered list. Two queries whatever the number of sites:
 * the facts, and the tenant's slug for the file name.
 */
export async function exportSitesXlsx(
  tenantId: number,
  filters: SiteDeploymentFilters,
  options: { timeZone?: string; now?: Date } = {},
): Promise<{ buffer: Buffer; fileName: string; rowCount: number }> {
  const now = options.now ?? new Date();
  const timeZone = options.timeZone ?? DEFAULT_EXPORT_TIME_ZONE;
  const [rows, tenant] = await Promise.all([
    listSiteDeployments(tenantId, filters, now.getTime()),
    db('tenants').where({ id: tenantId }).first<{ slug: string } | undefined>('slug'),
  ]);
  // God view: one workbook for every tenant, led by a "Client" column.
  const godView = rows.some((r) => r.tenantId !== undefined);
  const buffer = buildXlsx({
    sheetName: 'Sites',
    columns: godView ? [{ header: 'Client', width: 24, type: 'text' }, ...EXPORT_COLUMNS] : EXPORT_COLUMNS,
    rows: godView ? rows.map((r) => [r.tenantName ?? null, ...exportRow(r)]) : rows.map(exportRow),
    timeZone,
  });
  return {
    buffer,
    fileName: `sites-${godView ? 'tous-clients' : fileSlug(tenant?.slug)}-${isoDateIn(now, timeZone)}.xlsx`,
    rowCount: rows.length,
  };
}
