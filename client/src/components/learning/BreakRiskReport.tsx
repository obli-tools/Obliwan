import { useEffect, useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Play, ShieldAlert } from 'lucide-react';
import type { BreakRiskReport as Report, BreakRiskRow } from '@obliwan/shared';
import { Button } from '@/components/common/Button';
import { cn } from '@/utils/cn';
import { apiErrorText } from '@/components/variables/valueKinds';
import { learningApi, learningErrorCode } from '@/api/learning.api';
import { templatesApi, type Template, type TemplateRevision } from '@/api/templates.api';

/**
 * The break-risk report of one router: a template (the assigned one by
 * default, or a revision picked here) against what the router runs.
 * Read-only on the server: nothing is rendered for keeps, nothing is dialled.
 * Deliberately noisy — every difference is flagged unless proven harmless;
 * flagged rows first, grouped by domain. A server `detail` is shown verbatim.
 */
export function BreakRiskReport({ deviceId }: { deviceId: number }) {
  const { t } = useTranslation();
  const [templates, setTemplates] = useState<Template[]>([]);
  const [templateId, setTemplateId] = useState('');
  const [revisions, setRevisions] = useState<TemplateRevision[]>([]);
  const [revisionId, setRevisionId] = useState('');
  const [report, setReport] = useState<Report | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [showHarmless, setShowHarmless] = useState(false);

  useEffect(() => {
    templatesApi.list({ brand: 'mikrotik', includeLibrary: true }).then(setTemplates).catch(() => setTemplates([]));
  }, []);
  useEffect(() => {
    setRevisionId('');
    setRevisions([]);
    if (!templateId) return;
    templatesApi.revisions(templateId).then(setRevisions).catch(() => setRevisions([]));
  }, [templateId]);
  useEffect(() => {
    setReport(null);
    setError(null);
  }, [deviceId]);

  const run = async (): Promise<void> => {
    setLoading(true);
    setError(null);
    try {
      setReport(await learningApi.breakRisk(deviceId, revisionId || null));
    } catch (err) {
      const code = learningErrorCode(err);
      setError(code === 'no_snapshot' ? t('learning.breakRisk.noSnapshot') : apiErrorText(err) ?? String(err));
    } finally {
      setLoading(false);
    }
  };

  const groups = useMemo(() => {
    const rows = (report?.rows ?? []).filter((r) => showHarmless || r.verdict === 'flagged');
    const map = new Map<string, BreakRiskRow[]>();
    for (const r of rows) {
      const key = `${r.verdict}|${r.domain}`;
      const list = map.get(key) ?? [];
      list.push(r);
      map.set(key, list);
    }
    return [...map.entries()];
  }, [report, showHarmless]);

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-end gap-2">
        <label className="text-xs text-text-muted">
          {t('learning.breakRisk.revision')}
          <select
            className="mt-1 block rounded-md border border-border bg-bg-tertiary px-2 py-1 text-sm text-text-primary"
            value={templateId}
            onChange={(e) => setTemplateId(e.target.value)}
          >
            <option value="">{t('learning.breakRisk.assigned')}</option>
            {templates.map((tpl) => (
              <option key={tpl.id} value={tpl.id}>{tpl.name}</option>
            ))}
          </select>
        </label>
        {templateId && (
          <select
            className="rounded-md border border-border bg-bg-tertiary px-2 py-1 text-sm text-text-primary"
            value={revisionId}
            onChange={(e) => setRevisionId(e.target.value)}
          >
            <option value="">—</option>
            {revisions.map((r) => (
              <option key={r.id} value={r.id}>r{r.revision} · {r.status}</option>
            ))}
          </select>
        )}
        <Button size="sm" onClick={() => void run()} loading={loading} disabled={Boolean(templateId) && !revisionId}>
          <Play size={14} /> {t('learning.breakRisk.run')}
        </Button>
      </div>

      {error && <div className="rounded-md border border-red-500/40 bg-red-500/10 p-2 text-sm text-red-400">{error}</div>}

      {report && (
        <div className="space-y-2">
          <p className="text-xs text-text-muted">
            {report.revision
              ? `${report.revision.templateName ?? '?'} r${report.revision.revision}`
              : '—'}
            {report.snapshot ? ` · ${new Date(report.snapshot.capturedAt).toLocaleString()}` : ''}
          </p>
          {report.renderError && (
            <div className="rounded-md border border-amber-500/40 bg-amber-500/10 p-2 text-sm text-amber-400">
              {t('learning.breakRisk.renderError')} <span className="font-mono text-xs">{report.renderError}</span>
            </div>
          )}
          <div className="flex flex-wrap items-center gap-3 text-sm">
            <span className="flex items-center gap-1 text-red-400">
              <ShieldAlert size={14} /> {t('learning.breakRisk.flagged', { count: report.counts.flagged })}
            </span>
            <span className="text-emerald-400">{t('learning.breakRisk.harmless', { count: report.counts.harmless })}</span>
            <span className="text-text-muted">{t('learning.breakRisk.identical', { count: report.counts.identicalLines })}</span>
            <label className="ml-auto flex items-center gap-1 text-xs text-text-muted">
              <input type="checkbox" checked={showHarmless} onChange={(e) => setShowHarmless(e.target.checked)} />
              {t('learning.breakRisk.showHarmless')}
            </label>
          </div>
          {groups.map(([key, rows]) => {
            const [verdict, domain] = key.split('|');
            return (
              <div key={key} className="rounded-lg border border-border">
                <div className={cn(
                  'flex items-center justify-between rounded-t-lg px-2 py-1 text-xs font-medium',
                  verdict === 'flagged' ? 'bg-red-500/10 text-red-400' : 'bg-emerald-500/10 text-emerald-400',
                )}>
                  <span>{t(`learning.breakRisk.domain.${domain}`)}</span>
                  <span>{rows.length}</span>
                </div>
                <ul className="divide-y divide-border">
                  {rows.map((r, i) => (
                    <li key={i} className="px-2 py-1.5 text-xs">
                      <div className="flex flex-wrap items-center gap-1">
                        <span className="rounded bg-bg-tertiary px-1 text-[10px] text-text-muted">{t(`learning.breakRisk.source.${r.source}`)}</span>
                        {r.side && <span className="rounded bg-bg-tertiary px-1 text-[10px] text-text-muted">{t(`learning.breakRisk.side.${r.side}`)}</span>}
                        {r.risk && <span className="rounded bg-bg-tertiary px-1 text-[10px] text-text-muted">{r.risk}</span>}
                        {r.reasons.map((reason) => (
                          <span key={reason} className="rounded bg-amber-500/10 px-1 text-[10px] text-amber-400">
                            {t(`learning.breakRisk.reason.${reason}`)}
                          </span>
                        ))}
                      </div>
                      <div className="mt-0.5 break-all font-mono text-text-primary">{r.line}</div>
                      {r.detail && <div className="mt-0.5 text-text-muted">{r.detail}</div>}
                    </li>
                  ))}
                </ul>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
