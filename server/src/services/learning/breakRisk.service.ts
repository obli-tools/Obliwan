// ============================================================================
// Learning mode — the break-risk report of one router
// ============================================================================
//
// "What would this template break here?" — read-only: the template is
// rendered WITHOUT persisting (`persist: false`, a preview is not an intent),
// compared with the router's latest stored snapshot and its redacted export,
// and judged by `assessBreakRisk` (plan/breakRisk.ts). Writes nothing,
// dials nothing. It replaces the plan page for a router in learning, whose
// plan compile is refused.

import type { BreakRiskReport, PlanOp } from '@obliwan/shared';
import { db } from '../../db';
import { renderRevisionForDevice } from '../template/render.service';
import { getSnapshotRaw, latestDocument } from '../config/snapshot.service';
import { buildPlanOps } from '../plan/planner.service';
import { checkPlanUplinks } from '../plan/uplinkGuard';
import { assessBreakRisk } from '../plan/breakRisk';
import { parseRouterOsExport } from '../baseline/extrapolator/exportText';
import { compareEntriesDetailed } from '../baseline/extrapolator/reproduce';
import { LearningError, assertPlatformAdmin, type LearningActor } from './guard';

/** Lines compared on either side, at most. */
export const BREAK_RISK_LINE_CAP = 2000;

export async function breakRiskForDevice(
  tenantId: number,
  deviceId: number,
  revisionId: string | null,
  actor: LearningActor,
): Promise<BreakRiskReport> {
  assertPlatformAdmin(actor);
  const device = (await db('devices').where({ id: deviceId, tenant_id: tenantId }).first('id', 'name', 'tunnel_ip')) as
    | { id: number; name: string; tunnel_ip: string | null }
    | undefined;
  if (!device) throw new LearningError('DEVICE_NOT_FOUND', 'No such router in this workspace.', 404);

  const latest = await latestDocument(deviceId);
  if (!latest) {
    throw new LearningError(
      'no_snapshot',
      'This router has no configuration snapshot yet: capture it (or collect it) first.',
      409,
    );
  }
  const raw = await getSnapshotRaw(tenantId, latest.id);
  const snapshotRow = (await db('config_snapshots').where({ id: latest.id }).first('captured_at')) as { captured_at: Date } | undefined;
  const report: BreakRiskReport = {
    deviceId,
    deviceName: device.name,
    revision: null,
    snapshot: { id: latest.id, capturedAt: snapshotRow ? new Date(snapshotRow.captured_at).toISOString() : raw?.capturedAt ?? '' },
    renderError: null,
    counts: { flagged: 0, harmless: 0, identicalLines: 0 },
    rows: [],
  };

  let render: Awaited<ReturnType<typeof renderRevisionForDevice>>;
  try {
    render = await renderRevisionForDevice(tenantId, deviceId, { persist: false, revisionId });
  } catch (err) {
    report.renderError = (err instanceof Error ? err.message : String(err)).slice(0, 1000);
    return report;
  }
  const tpl = render.templateId
    ? ((await db('templates').where({ id: render.templateId }).first('name')) as { name: string } | undefined)
    : undefined;
  report.revision = { id: render.revisionId, templateName: tpl?.name ?? null, revision: render.revision };
  if (render.status !== 'ok' || !render.ncmDesired || render.body === null) {
    report.renderError = `${render.errorKind ?? 'render_failed'}: ${(render.errorMessage ?? 'no reason recorded').slice(0, 1000)}`;
    return report;
  }

  const planned = buildPlanOps({
    desired: render.ncmDesired,
    observed: latest.doc,
    claimedKinds: render.claimedKinds,
    deviceId,
    tunnelIp: device.tunnel_ip,
  });
  const uplink = checkPlanUplinks(latest.doc, planned.ops);
  const bySeq = new Map<number, string[]>();
  for (const v of uplink.violations) {
    if (v.opSeq === null) continue;
    const list = bySeq.get(v.opSeq) ?? [];
    list.push(`${v.message} [${v.code}]`);
    bySeq.set(v.opSeq, list);
  }

  const actualEntries = raw ? parseRouterOsExport(raw.text).entries : [];
  const renderedEntries = parseRouterOsExport(render.body).entries;
  const comparison = raw ? compareEntriesDetailed(actualEntries, renderedEntries, BREAK_RISK_LINE_CAP) : null;

  report.rows = assessBreakRisk({
    ops: planned.ops as PlanOp[],
    signals: planned.signals,
    uplinkRefusalsBySeq: bySeq,
    comparison,
    actualEntries,
  });
  report.counts = {
    flagged: report.rows.filter((r) => r.verdict === 'flagged').length,
    harmless: report.rows.filter((r) => r.verdict === 'harmless').length,
    identicalLines: comparison?.matched ?? 0,
  };
  // Flagged first, then by domain, keeping each group's own order.
  report.rows = report.rows
    .map((r, i) => ({ r, i }))
    .sort((a, b) =>
      (a.r.verdict === b.r.verdict ? 0 : a.r.verdict === 'flagged' ? -1 : 1)
      || a.r.domain.localeCompare(b.r.domain)
      || a.i - b.i)
    .map(({ r }) => r);
  return report;
}
