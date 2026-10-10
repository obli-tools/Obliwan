import { useEffect, useRef, useState, type FormEvent } from 'react';
import { useTranslation } from 'react-i18next';
import toast from 'react-hot-toast';
import { AlertTriangle, Ban } from 'lucide-react';
import { templatesApi, type Template, type TemplateRevision } from '@/api/templates.api';
import { Button } from '@/components/common/Button';

/**
 * Deprecate ONE published revision — the confirmation, and the one-click offer
 * made right after a newer revision of the same template is published.
 *
 * Why it exists: the provisioning bench offers every PUBLISHED revision of an
 * active MikroTik template (`listBenchCandidates` reads `status = 'published'`,
 * and the bench compile re-checks against that same list), so a revision that
 * was superseded but never deprecated stays on the bench's list for good.
 *
 * What the dialog says is what the server does, and nothing more:
 *   - the bench stops offering it, and a compile naming it is refused;
 *   - a new rollout of it is refused (`rollout.service`: published only);
 *   - the assignment resolver passes over it: a `latest_published` assignment
 *     falls to the newest OTHER published revision that fits the router, or to
 *     none, and a `pinned` assignment stops applying (its revision must be
 *     published) — counted per revision by `GET /templates/:id/revisions`;
 *   - renders, plans and rollouts already made from it keep it;
 *   - the server offers no way back to `published` (the status schema accepts
 *     `quarantined` and `deprecated` only), so the way to offer the content
 *     again is the editor's "New revision from this one", then publishing.
 *
 * The reason is required by the server and kept in the audit log; after a
 * publication it is pre-filled with "superseded by #N", editable — unless the
 * two revisions cover different RouterOS versions, where "superseded" would
 * not be true and the operator writes the reason. Deprecation cannot be undone,
 * so when the dialog is the post-publish offer the focus is on "Keep #N
 * published", not on the pre-filled field: a stray Enter keeps the revision.
 * The server also refuses a revision a rollout still holds, and that refusal is
 * shown here as it comes back.
 */
export interface RevisionDeprecateDialogProps {
  template: Template;
  /** The PUBLISHED revision to deprecate. */
  revision: TemplateRevision;
  /** Set when offered right after a publication: the revision just published. */
  supersededBy?: TemplateRevision | null;
  onClose: () => void;
  onDeprecated: (updated: TemplateRevision) => void;
}

export function RevisionDeprecateDialog({
  template, revision, supersededBy = null, onClose, onDeprecated,
}: RevisionDeprecateDialogProps) {
  const { t } = useTranslation();
  const osDiffers = supersededBy !== null
    && ((supersededBy.osMin ?? null) !== (revision.osMin ?? null)
      || (supersededBy.osMax ?? null) !== (revision.osMax ?? null));
  const [reason, setReason] = useState(() => (supersededBy && !osDiffers
    ? t('templates.deprecate.reasonSuperseded', {
      defaultValue: 'Superseded by revision #{{n}}',
      n: supersededBy.revision,
    })
    : ''));
  const [sending, setSending] = useState(false);
  /** Set synchronously: two Enters in one tick both see `sending === false`. */
  const sendingRef = useRef(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape' && !sending) onClose(); };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [onClose, sending]);

  const osWindow = (r: TemplateRevision): string => {
    const parts = [r.osMin ? `≥ ${r.osMin}` : null, r.osMax ? `≤ ${r.osMax}` : null].filter(Boolean);
    return parts.length > 0
      ? `RouterOS ${parts.join(' ')}`
      : t('templates.deprecate.anyOs', { defaultValue: 'any RouterOS version' });
  };
  const pinned = revision.pinnedAssignments;

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (sendingRef.current) return;
    const why = reason.trim();
    if (!why) return;
    sendingRef.current = true;
    setSending(true);
    setError(null);
    try {
      const updated = await templatesApi.setStatus(revision.id, 'deprecated', why.slice(0, 1000));
      toast.success(t('templates.deprecate.done', {
        defaultValue: 'Revision #{{n}} deprecated: the bench no longer offers it',
        n: revision.revision,
      }));
      onDeprecated(updated);
    } catch (err) {
      const m = (err as { response?: { data?: { error?: string } } }).response?.data?.error;
      setError(m ?? t('templates.deprecate.failed', { defaultValue: 'Could not deprecate the revision' }));
    } finally {
      sendingRef.current = false;
      setSending(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center overflow-y-auto bg-black/60 p-4">
      <form
        role="dialog"
        aria-modal="true"
        aria-labelledby="revision-deprecate-title"
        onSubmit={(e) => void submit(e)}
        className="my-8 w-full max-w-xl rounded-xl border border-border bg-bg-secondary shadow-2xl"
      >
        <div className="flex items-center gap-2 border-b border-border px-5 py-4">
          <Ban size={18} className="text-status-ssl-warning" />
          <h2 id="revision-deprecate-title" className="text-base font-semibold text-text-primary">
            {supersededBy
              ? t('templates.deprecate.titleAfterPublish', {
                defaultValue: 'Revision #{{n}} is published. Deprecate revision #{{prev}}?',
                n: supersededBy.revision,
                prev: revision.revision,
              })
              : t('templates.deprecate.title', {
                defaultValue: 'Deprecate revision #{{n}} of "{{name}}"?',
                n: revision.revision,
                name: template.name,
              })}
          </h2>
        </div>

        <div className="space-y-3 p-5 text-sm text-text-secondary">
          {supersededBy && (
            <p>
              {t('templates.deprecate.introAfterPublish', {
                defaultValue:
                  'Revision #{{prev}} is still published, so the provisioning bench keeps offering it '
                  + 'beside #{{n}}. Deprecating it is how it stops being offered.',
                n: supersededBy.revision,
                prev: revision.revision,
              })}
            </p>
          )}

          {osDiffers && supersededBy && (
            <p className="flex items-start gap-1.5 rounded-md border border-status-ssl-warning/40 bg-status-ssl-warning/5 p-2 text-status-ssl-warning">
              <AlertTriangle size={14} className="mt-0.5 shrink-0" />
              <span>
                {t('templates.deprecate.osDiffers', {
                  defaultValue:
                    'They do not cover the same RouterOS versions (#{{prev}}: {{prevOs}} · #{{n}}: {{nextOs}}). '
                    + 'A router that only #{{prev}} fits would no longer receive this template.',
                  prev: revision.revision,
                  prevOs: osWindow(revision),
                  n: supersededBy.revision,
                  nextOs: osWindow(supersededBy),
                })}
              </span>
            </p>
          )}

          <div>
            <p className="mb-1 font-medium text-text-primary">
              {t('templates.deprecate.whatHeading', { defaultValue: 'What deprecating does' })}
            </p>
            <ul className="list-disc space-y-1 pl-5">
              <li>
                {t('templates.deprecate.bench', {
                  defaultValue:
                    'The provisioning bench stops offering it, and a bench compile that still names it is refused.',
                })}
              </li>
              <li>{t('templates.deprecate.rollout', { defaultValue: 'A new rollout of it is refused.' })}</li>
              <li>
                {t('templates.deprecate.latest', {
                  defaultValue:
                    'A router that receives it through an assignment following the latest published revision '
                    + 'moves to the newest other published revision that fits it, or receives none if no other fits.',
                })}
              </li>
              <li className={pinned !== undefined && pinned > 0 ? 'font-medium text-status-ssl-warning' : undefined}>
                {pinned === undefined
                  ? t('templates.deprecate.pinnedUnknown', {
                    defaultValue:
                      'Assignments pinned to this revision stop applying it until they are pinned to another revision.',
                  })
                  : pinned === 0
                    ? t('templates.deprecate.pinnedNone', {
                      defaultValue: 'No enabled assignment is pinned to this revision.',
                    })
                    : t('templates.deprecate.pinnedCount', {
                      defaultValue:
                        'Enabled assignments pinned to this revision: {{n}}. They stop applying it until they '
                        + 'are pinned to another revision.',
                      n: pinned,
                    })}
              </li>
              <li>
                {t('templates.deprecate.kept', {
                  defaultValue:
                    'Renders, plans and rollouts already made from it keep it. The revision itself stays, frozen, '
                    + 'as the record of what it produced.',
                })}
              </li>
              <li>
                {t('templates.deprecate.noUndo', {
                  defaultValue:
                    'There is no way back to published. To offer the same content again, open it, use '
                    + '"New revision from this one" and publish that.',
                })}
              </li>
            </ul>
          </div>

          <div className="space-y-1">
            <label htmlFor="revision-deprecate-reason" className="block font-medium text-text-secondary">
              {t('templates.deprecate.reasonLabel', { defaultValue: 'Reason (kept in the audit log)' })}
            </label>
            <input
              id="revision-deprecate-reason"
              className="w-full rounded-md border border-border bg-bg-tertiary px-3 py-2 text-sm text-text-primary placeholder:text-text-muted focus:border-transparent focus:outline-none focus:ring-2 focus:ring-accent"
              value={reason}
              maxLength={1000}
              autoFocus={!supersededBy}
              required
              placeholder={t('templates.deprecate.reasonPlaceholder', { defaultValue: 'Why this revision is retired' })}
              onChange={(e) => setReason(e.target.value)}
            />
          </div>

          {error && <p className="text-status-down">{error}</p>}
        </div>

        <div className="flex flex-wrap justify-end gap-2 border-t border-border px-5 py-3">
          <Button
            type="button"
            size="sm"
            variant="secondary"
            onClick={onClose}
            disabled={sending}
            autoFocus={supersededBy !== null}
          >
            {supersededBy
              ? t('templates.deprecate.keep', {
                defaultValue: 'Keep #{{n}} published',
                n: revision.revision,
              })
              : t('common.cancel')}
          </Button>
          <Button type="submit" size="sm" variant="danger" loading={sending} disabled={reason.trim() === ''}>
            <Ban size={14} className="mr-1.5" />
            {t('templates.deprecate.confirm', { defaultValue: 'Deprecate #{{n}}', n: revision.revision })}
          </Button>
        </div>
      </form>
    </div>
  );
}
