import { useCallback, useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import toast from 'react-hot-toast';
import { FileCode, Trash2 } from 'lucide-react';
import {
  templatesApi,
  type DeviceTemplateResolution,
  type TemplateAssignment,
  type TemplateRevision,
} from '@/api/templates.api';

/**
 * Which template revision this device's previews, plans and rollouts render,
 * and the assignments made for the device itself — the one a bench compile
 * writes (pinned to the revision the box was compiled with) or one made by
 * hand. Small on purpose: it shows the resolver's answer as the server gives
 * it (`GET /templates/devices/:id/resolution`) and lets a TEMPLATE_WRITE user
 * re-pin or remove a DEVICE-scoped assignment. Assignments at wider scopes
 * are not edited from a device page: changing one changes every device under
 * it.
 */
export function DeviceTemplateCard({
  deviceId,
  canWrite,
  embedded = false,
  onView,
}: {
  deviceId: number;
  canWrite: boolean;
  /** Drawn inside a device-page section that already carries the frame and
   *  the title: the card then draws neither. */
  embedded?: boolean;
  /** The resolver's answer once read (`null`: it could not be) — the device
   *  page's one-line summary of this section. */
  onView?: (resolution: DeviceTemplateResolution | null) => void;
}) {
  const { t } = useTranslation();
  const [resolution, setResolution] = useState<DeviceTemplateResolution | null>(null);
  const [assignments, setAssignments] = useState<TemplateAssignment[]>([]);
  const [revisions, setRevisions] = useState<Record<string, TemplateRevision[]>>({});
  const [loadError, setLoadError] = useState(false);
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    try {
      const [res, all] = await Promise.all([templatesApi.deviceResolution(deviceId), templatesApi.listAssignments()]);
      const own = all.filter((a) => a.scope === 'device' && a.scopeId === deviceId);
      setResolution(res);
      setAssignments(own);
      setLoadError(false);
      if (canWrite) {
        const ids = [...new Set(own.map((a) => a.templateId))];
        const lists = await Promise.all(ids.map((id) => templatesApi.revisions(id).catch(() => [] as TemplateRevision[])));
        setRevisions(Object.fromEntries(ids.map((id, i) => [id, lists[i]])));
      }
    } catch {
      setLoadError(true);
    }
  }, [deviceId, canWrite]);

  useEffect(() => {
    void load();
  }, [load]);

  useEffect(() => {
    if (resolution) onView?.(resolution);
    else if (loadError) onView?.(null);
  }, [resolution, loadError, onView]);

  const repin = async (a: TemplateAssignment, value: string) => {
    setBusy(true);
    try {
      await templatesApi.setAssignmentRevision(a.id, value === '' ? null : value);
      toast.success(t('deviceTemplate.saved', { defaultValue: 'Assignment updated' }));
      await load();
    } catch {
      toast.error(t('deviceTemplate.saveError', { defaultValue: 'The assignment could not be changed' }));
    } finally {
      setBusy(false);
    }
  };

  const remove = async (a: TemplateAssignment) => {
    setBusy(true);
    try {
      await templatesApi.removeAssignment(a.id);
      toast.success(t('deviceTemplate.removed', { defaultValue: 'Assignment removed' }));
      await load();
    } catch {
      toast.error(t('deviceTemplate.saveError', { defaultValue: 'The assignment could not be changed' }));
    } finally {
      setBusy(false);
    }
  };

  const applied = resolution?.selected[0] ?? null;

  return (
    <section className={embedded ? undefined : 'rounded-lg border border-border bg-bg-secondary p-4'}>
      {!embedded && (
        <h2 className="mb-3 flex items-center gap-1.5 text-sm font-semibold uppercase tracking-wide text-text-secondary">
          <FileCode size={14} />
          {t('deviceTemplate.title', { defaultValue: 'Template' })}
        </h2>
      )}
      {loadError && !resolution ? (
        <p className="text-sm text-text-muted">
          {t('deviceTemplate.loadError', { defaultValue: 'The template assignment could not be read.' })}
        </p>
      ) : !resolution ? (
        <p className="text-sm text-text-muted">…</p>
      ) : (
        <div className="space-y-3 text-sm">
          {applied ? (
            <p className="text-text-primary">
              <Link to={`/templates?template=${applied.templateId}${applied.revisionId ? `&revision=${applied.revisionId}` : ''}`} className="text-accent hover:underline">{applied.templateName}</Link>
              {' — '}
              {applied.revision !== null
                ? t('deviceTemplate.revision', { n: applied.revision, defaultValue: 'revision {{n}}' })
                : '—'}
              <span className="ml-2 text-xs text-text-muted">
                {t(`deviceTemplate.scope.${applied.scope}`, { defaultValue: applied.scope })}
                {', '}
                {applied.pinMode === 'pinned'
                  ? t('deviceTemplate.pinned', { defaultValue: 'pinned' })
                  : t('deviceTemplate.latest', { defaultValue: 'latest published' })}
              </span>
            </p>
          ) : (
            <div>
              <p className="text-text-muted">{t('deviceTemplate.none', { defaultValue: 'No template revision applies to this device.' })}</p>
              {resolution.rejected.length > 0 && (
                <ul className="mt-1 space-y-0.5 text-xs text-text-muted">
                  {resolution.rejected.slice(0, 3).map((r) => (
                    <li key={`${r.assignmentId}-${r.reason}`}>{r.templateName}: {r.detail}</li>
                  ))}
                </ul>
              )}
            </div>
          )}

          <div>
            <h3 className="text-[11px] uppercase tracking-wider text-text-muted">
              {t('deviceTemplate.deviceAssignments', { defaultValue: 'Assigned to this device' })}
            </h3>
            {assignments.length === 0 ? (
              <p className="mt-1 text-xs text-text-muted">
                {t('deviceTemplate.noDeviceAssignment', { defaultValue: 'None: the device follows its group or workspace assignments.' })}
              </p>
            ) : (
              <ul className="mt-1 space-y-2">
                {assignments.map((a) => {
                  const published = (revisions[a.templateId] ?? []).filter((r) => r.status === 'published' || r.id === a.revisionId);
                  return (
                    <li key={a.id} className="rounded-md border border-border p-2">
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="font-medium text-text-primary">{a.templateName}</span>
                        {canWrite ? (
                          <select
                            value={a.revisionId ?? ''}
                            disabled={busy}
                            onChange={(e) => void repin(a, e.target.value)}
                            className="rounded-md border border-border bg-bg-tertiary px-2 py-1 text-xs text-text-primary"
                          >
                            <option value="">{t('deviceTemplate.followLatest', { defaultValue: 'Follow the latest published revision' })}</option>
                            {published.map((r) => (
                              <option key={r.id} value={r.id}>
                                {t('deviceTemplate.revision', { n: r.revision, defaultValue: 'revision {{n}}' })}
                                {r.status !== 'published' ? ` (${r.status})` : ''}
                              </option>
                            ))}
                            {/* The pin itself, while its revision list is not
                                (or cannot be) read: never shown as "follow
                                the latest", which is not what is stored. */}
                            {a.revisionId !== null && !published.some((r) => r.id === a.revisionId) && (
                              <option value={a.revisionId}>{t('deviceTemplate.pinned', { defaultValue: 'pinned' })} #{a.revisionId}</option>
                            )}
                          </select>
                        ) : (
                          <span className="text-xs text-text-muted">
                            {a.pinMode === 'pinned'
                              ? t('deviceTemplate.pinned', { defaultValue: 'pinned' })
                              : t('deviceTemplate.latest', { defaultValue: 'latest published' })}
                          </span>
                        )}
                        {canWrite && (
                          <button
                            type="button"
                            disabled={busy}
                            onClick={() => void remove(a)}
                            className="ml-auto rounded p-1 text-text-muted hover:bg-bg-hover hover:text-status-down"
                            title={t('deviceTemplate.remove', { defaultValue: 'Remove this assignment' })}
                          >
                            <Trash2 size={13} />
                          </button>
                        )}
                      </div>
                      {a.reason && <p className="mt-1 text-xs text-text-muted">{a.reason}</p>}
                    </li>
                  );
                })}
              </ul>
            )}
          </div>
        </div>
      )}
    </section>
  );
}
