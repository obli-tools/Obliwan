import { useEffect, useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Link } from 'react-router-dom';
import { CheckCircle2, ChevronDown, ChevronRight, Link2, MinusCircle, X, XCircle } from 'lucide-react';
import {
  RECONCILE_ATTACH_APPLY_MAX_SITES,
  RECONCILE_ATTACH_CREDENTIAL_REASONS,
  RECONCILE_ATTACH_FOLLOWUP_DEFAULTS,
  type ReconcileAttachFollowUpKind,
  type ReconcileAttachFollowUpPlan,
  type ReconcileAttachFollowUpResult,
  type ReconcileAttachPreview,
  type ReconcileAttachPreviewRow,
  type ReconcileAttachReason,
  type ReconcileAttachResultRow,
  type PppDuplicateSession,
} from '@obliwan/shared';
import { Button } from '@/components/common/Button';
import { Input } from '@/components/common/Input';
import { reconcileApi, reconcileError, type ReconcileAttachCredentials } from '@/api/reconcile.api';
import { learningApi } from '@/api/learning.api';

interface Props {
  onClose: () => void;
  /** Called once routers were attached, so the page re-reads the reconciliation. */
  onAttached: () => void;
}

const TH = 'px-2 py-1.5 text-left text-xs font-medium text-text-muted';
const TD = 'px-2 py-1.5 text-sm text-text-primary align-top';

/** Refused only for want of a usable vault password: a typed one may do. */
function needsCredential(r: ReconcileAttachPreviewRow): boolean {
  return r.verdict !== 'eligible' && r.reason !== null && RECONCILE_ATTACH_CREDENTIAL_REASONS.includes(r.reason);
}

/**
 * "Attach the online routers" of the reconciliation (server:
 * `/api/reconcile/attach-devices[/preview]`, a platform administrator's:
 * the act binds logins of the shared concentrator to devices).
 *
 * Three steps, each saying what it does: the list of the workspace's online
 * routers that have no device yet (the dry run over every site), an optional
 * SSH credential (empty = `admin` and the vault's `admin_password`), a dry run
 * of the selection with that credential — dials nothing — and the act, sent in
 * slices of RECONCILE_ATTACH_APPLY_MAX_SITES so no request outlives the proxy.
 * The list comes from a dry run WITHOUT a credential, so a site whose only
 * refusal is the vault's (RECONCILE_ATTACH_CREDENTIAL_REASONS: no password,
 * an invalid one) is listed as selectable
 * too: the typed credential exists for exactly those, and the dry run of the
 * selection is what judges them with it.
 * The act is offered only for the selection, credential and follow-up options
 * the last dry run judged. The password lives in this component's state only,
 * and is sent with each request; no answer ever carries it back.
 *
 * What follows the attach (server: reconcileAttach.service.ts, "WHAT FOLLOWS
 * THE ATTACH"): by default each attached router gets its management_access
 * job (ObliWAN's own `obliwan` account, API-SSL), and the template fixes
 * (legacy_compliance) are queued by the worker once that job has succeeded.
 * Neither arms a dead-man, so ONE explicit confirmation of the degraded level
 * covers the batch, and the act stays disabled until it is ticked. The
 * confirmation is not part of the dry run's key: it changes nothing the dry
 * run says.
 */
export function AttachDevicesDialog({ onClose, onAttached }: Props) {
  const { t } = useTranslation();
  const [all, setAll] = useState<ReconcileAttachPreview | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [selected, setSelected] = useState<Set<number>>(new Set());
  const [showSkipped, setShowSkipped] = useState(false);
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [openManagementAccess, setOpenManagementAccess] = useState(RECONCILE_ATTACH_FOLLOWUP_DEFAULTS.openManagementAccess);
  const [applyComplianceChecked, setApplyComplianceChecked] = useState(RECONCILE_ATTACH_FOLLOWUP_DEFAULTS.applyCompliance);
  const [confirmNoDeadman, setConfirmNoDeadman] = useState(false);
  // Operator request 2026-10-09: checked by default. The attach puts each
  // attached router in learning mode; the capture starts once every slice
  // is attached (one capture run per workspace at a time).
  const [putInLearning, setPutInLearning] = useState(true);
  const [learningOutcome, setLearningOutcome] = useState<
    { enabled: number; errors: string[]; capture: { total: number } | { error: string } | null } | null
  >(null);
  const [dry, setDry] = useState<{ key: string; preview: ReconcileAttachPreview } | null>(null);
  const [busy, setBusy] = useState<'dry' | 'apply' | null>(null);
  const [progress, setProgress] = useState<{ done: number; total: number } | null>(null);
  const [results, setResults] = useState<ReconcileAttachResultRow[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let live = true;
    reconcileApi
      .attachPreview({})
      .then((p) => {
        if (!live) return;
        setAll(p);
        setSelected(new Set(p.rows.filter((r) => r.verdict === 'eligible').map((r) => r.siteId)));
      })
      .catch((err) => live && setLoadError(reconcileError(err).message));
    return () => {
      live = false;
    };
  }, []);

  // Selectable: eligible as is, or once a credential is typed.
  const eligible = useMemo(() => (all?.rows ?? []).filter((r) => r.verdict === 'eligible' || needsCredential(r)), [all]);
  const skipped = useMemo(() => (all?.rows ?? []).filter((r) => r.verdict !== 'eligible' && !needsCredential(r)), [all]);

  const typed = username.trim() !== '' || password !== '';
  const incomplete = typed && (username.trim() === '' || password === '');
  const credentials: ReconcileAttachCredentials | undefined = typed && !incomplete ? { username: username.trim(), password } : undefined;
  const selection = eligible.filter((r) => selected.has(r.siteId)).map((r) => r.siteId);
  const selectedNeedingCredential = credentials ? 0 : eligible.filter((r) => needsCredential(r) && selected.has(r.siteId)).length;
  const sharedPasswordCount =
    dry?.preview.rows.filter((r) => r.verdict === 'eligible' && r.credentialSource === 'vault' && r.vaultScope === 'instance').length ?? 0;
  // No compliance without management access: it waits for that job.
  const followUps = { openManagementAccess, applyCompliance: openManagementAccess && applyComplianceChecked };
  const needsConfirmation = followUps.openManagementAccess;
  // What the dry run judged; any change asks for a new one.
  const key = JSON.stringify([
    selection,
    credentials ? [credentials.username, credentials.password] : null,
    followUps.openManagementAccess,
    followUps.applyCompliance,
  ]);
  const dryCurrent = dry !== null && dry.key === key;
  const toApply = dryCurrent ? dry.preview.rows.filter((r) => r.verdict === 'eligible').map((r) => r.siteId) : [];

  const reasonText = (r: ReconcileAttachReason | null): string =>
    r === null ? '' : t(`reconcileAttach.reason.${r}`, { defaultValue: r });

  /** `duplicate_sessions`: the sessions the concentrator lists for the
   *  account, by caller-id and uptime, so the operator finds the extra box. */
  const DuplicateSessions = ({ sessions }: { sessions: PppDuplicateSession[] | undefined }) =>
    sessions && sessions.length > 0 ? (
      <div className="mt-0.5 text-[11px] text-red-400">
        {sessions.map((s, i) => (
          <div key={i} className="whitespace-nowrap">
            {t('reconcileAttach.duplicateSession', {
              defaultValue: 'session from {{caller}} — up {{uptime}}',
              caller: s.callerId ?? '?',
              uptime: s.uptime ?? '?',
            })}
          </div>
        ))}
      </div>
    ) : null;

  const jobText = (kind: ReconcileAttachFollowUpKind): string =>
    t(`reconcileAttach.followUps.kind.${kind}`, {
      defaultValue: kind === 'management_access' ? 'Management access' : 'Template fixes',
    });

  /** The dry run's word on one follow-up. The server's sentence (French, the
   *  job services') is shown as it is, like the device cards do. */
  const planText = (p: ReconcileAttachFollowUpPlan): string =>
    p.plan === 'queue'
      ? t('reconcileAttach.followUps.plan.queue', { defaultValue: 'then the management access job is queued' })
      : p.plan === 'after'
        ? t('reconcileAttach.followUps.plan.after', {
            defaultValue: 'then the template fixes, queued once management access has succeeded',
          })
        : t('reconcileAttach.followUps.plan.refused', {
            defaultValue: '{{job}} would be refused: {{message}}',
            job: jobText(p.kind),
            message: p.message ?? p.reason ?? '',
          });

  const resultText = (f: ReconcileAttachFollowUpResult): string => {
    const job = jobText(f.kind);
    const message = f.message ?? f.reason ?? '';
    switch (f.status) {
      case 'queued':
        return t('reconcileAttach.followUps.status.queued', { defaultValue: '{{job}}: queued (job #{{id}})', job, id: f.jobId });
      case 'pending':
        return t('reconcileAttach.followUps.status.pending', {
          defaultValue: '{{job}}: scheduled, queued once management access has succeeded',
          job,
        });
      case 'refused':
        return t('reconcileAttach.followUps.status.refused', { defaultValue: '{{job}}: refused — {{message}}', job, message });
      default:
        return t('reconcileAttach.followUps.status.skipped', { defaultValue: '{{job}}: not scheduled — {{message}}', job, message });
    }
  };

  const toggle = (id: number) =>
    setSelected((s) => {
      const n = new Set(s);
      if (n.has(id)) n.delete(id);
      else n.add(id);
      return n;
    });
  const allChecked = eligible.length > 0 && eligible.every((r) => selected.has(r.siteId));

  const runDry = async () => {
    setBusy('dry');
    setError(null);
    try {
      const preview = await reconcileApi.attachPreview({ siteIds: selection, credentials, ...followUps });
      setDry({ key, preview });
    } catch (err) {
      setError(reconcileError(err).message);
    } finally {
      setBusy(null);
    }
  };

  const apply = async () => {
    setBusy('apply');
    setError(null);
    const out: ReconcileAttachResultRow[] = [];
    const learningIds: number[] = [];
    const learningErrors: string[] = [];
    setResults([]);
    setLearningOutcome(null);
    setProgress({ done: 0, total: toApply.length });
    try {
      for (let i = 0; i < toApply.length; i += RECONCILE_ATTACH_APPLY_MAX_SITES) {
        const slice = toApply.slice(i, i + RECONCILE_ATTACH_APPLY_MAX_SITES);
        const r = await reconcileApi.attachApply({
          siteIds: slice,
          credentials,
          ...followUps,
          confirmNoDeadman: needsConfirmation && confirmNoDeadman,
          learning: putInLearning,
        });
        out.push(...r.rows);
        if (r.learning) {
          learningIds.push(...r.learning.enabled);
          if (r.learning.error) learningErrors.push(r.learning.error);
        }
        setResults([...out]);
        setProgress({ done: Math.min(i + slice.length, toApply.length), total: toApply.length });
      }
    } catch (err) {
      setError(reconcileError(err).message);
    } finally {
      // The routers now in learning: one capture for all of them. A refusal
      // (a capture of this workspace still running, say) is shown beside the
      // attach, which stands.
      if (putInLearning && (learningIds.length > 0 || learningErrors.length > 0)) {
        let capture: { total: number } | { error: string } | null = null;
        if (learningIds.length > 0) {
          try {
            const c = await learningApi.startCapture(learningIds);
            capture = { total: c.total };
          } catch (err) {
            capture = { error: reconcileError(err).message };
          }
        }
        setLearningOutcome({ enabled: learningIds.length, errors: learningErrors, capture });
      }
      setBusy(null);
      setDry(null);
      if (out.some((r) => r.outcome === 'attached')) onAttached();
    }
  };

  const scopeText = (row: ReconcileAttachPreviewRow) =>
    row.credentialSource === 'operator'
      ? t('reconcileAttach.source.operator', { defaultValue: 'password typed above' })
      : t('reconcileAttach.source.vault', {
          defaultValue: 'vault password ({{scope}} level)',
          scope: t(`reconcileAttach.scope.${row.vaultScope ?? 'instance'}`, { defaultValue: row.vaultScope ?? 'instance' }),
        });

  const DeviceLink = ({ d }: { d: { id: number; name: string } | null }) =>
    d ? (
      <Link to={`/devices/${d.id}`} className="text-accent hover:underline" onClick={onClose}>
        {d.name}
      </Link>
    ) : null;

  const SiteCell = ({ row }: { row: { siteId: number; code: string | null; name: string | null } }) => (
    <td className={TD}>
      {row.code !== null ? (
        <>
          <span className="font-mono">{row.code}</span> <span className="text-text-muted">{row.name}</span>
        </>
      ) : (
        <span className="text-text-muted">#{row.siteId}</span>
      )}
    </td>
  );

  const counts = results
    ? {
        attached: results.filter((r) => r.outcome === 'attached').length,
        failed: results.filter((r) => r.outcome === 'failed').length,
        skipped: results.filter((r) => r.outcome === 'skipped').length,
      }
    : null;

  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center overflow-y-auto bg-black/60 p-4">
      <div className="my-8 w-full max-w-5xl rounded-xl border border-border bg-bg-secondary shadow-2xl">
        <div className="flex items-center gap-2 border-b border-border px-5 py-4">
          <Link2 size={18} className="text-accent" />
          <h2 className="flex-1 text-base font-semibold text-text-primary">
            {t('reconcileAttach.title', { defaultValue: 'Attach the online routers' })}
          </h2>
          <button
            type="button"
            onClick={onClose}
            disabled={busy === 'apply'}
            className="rounded p-1 text-text-muted hover:text-text-primary disabled:opacity-50"
            aria-label={t('reconcileAttach.close', { defaultValue: 'Close' })}
          >
            <X size={16} />
          </button>
        </div>

        <div className="space-y-4 p-5">
          <p className="text-sm text-text-muted">
            {t('reconcileAttach.intro', {
              defaultValue:
                "Each selected router is reached over SSH on its tunnel address and must prove it is the site's router (its management tunnel, the L2TP client named l2tp-mgmt — or, when there is none, the only one using the site's account — dials with the site's account); its identity, serial number, model and RouterOS version are read. Only then is it created, active and managed, with that SSH credential. The attach itself writes nothing to the routers and creates no account on them; the management access job, queued right after it when the option below is ticked, creates ObliWAN's own account, opens API-SSL and switches ObliWAN to that account, and the template fixes follow once it has succeeded.",
            })}
          </p>

          {loadError && <p className="text-sm text-status-down">{loadError}</p>}
          {!all && !loadError && (
            <p className="text-sm text-text-muted">{t('reconcileAttach.loading', { defaultValue: 'Reading the sites…' })}</p>
          )}

          {all && results === null && (
            <>
              {/* ── The online routers without a device ───────────────── */}
              <div>
                <h3 className="mb-2 text-sm font-semibold text-text-primary">
                  {t('reconcileAttach.eligible.title', { defaultValue: 'Online routers to attach ({{count}})', count: eligible.length })}
                </h3>
                {eligible.length === 0 ? (
                  <p className="text-sm text-text-muted">
                    {t('reconcileAttach.eligible.none', { defaultValue: 'No online router left to attach.' })}
                  </p>
                ) : (
                  <div className="max-h-72 overflow-auto rounded-md border border-border">
                    <table className="w-full">
                      <thead>
                        <tr>
                          <th className={TH}>
                            <input
                              type="checkbox"
                              checked={allChecked}
                              onChange={() => setSelected(allChecked ? new Set() : new Set(eligible.map((r) => r.siteId)))}
                              aria-label={t('reconcileAttach.selectAll', { defaultValue: 'Select all' })}
                            />
                          </th>
                          <th className={TH}>{t('reconcileAttach.col.site', { defaultValue: 'Site' })}</th>
                          <th className={TH}>{t('reconcileAttach.col.login', { defaultValue: 'CHR account' })}</th>
                          <th className={TH}>{t('reconcileAttach.col.address', { defaultValue: 'Tunnel address' })}</th>
                          <th className={TH} />
                        </tr>
                      </thead>
                      <tbody>
                        {eligible.map((r) => (
                          <tr key={r.siteId} className="border-t border-border">
                            <td className={TD}>
                              <input type="checkbox" checked={selected.has(r.siteId)} onChange={() => toggle(r.siteId)} />
                            </td>
                            <SiteCell row={r} />
                            <td className={`${TD} font-mono text-xs`}>{r.login}</td>
                            <td className={`${TD} font-mono text-xs`}>{r.tunnelIp}</td>
                            <td className={`${TD} text-xs text-amber-400`}>
                              {needsCredential(r) &&
                                t('reconcileAttach.needsCredential.badge', {
                                  defaultValue: 'type a credential: {{reason}}',
                                  reason: reasonText(r.reason),
                                })}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>

              {skipped.length > 0 && (
                <div>
                  <button
                    type="button"
                    className="flex items-center gap-1 text-sm font-semibold text-text-primary"
                    onClick={() => setShowSkipped((v) => !v)}
                  >
                    {showSkipped ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
                    {t('reconcileAttach.skipped.title', { defaultValue: 'Not attachable ({{count}})', count: skipped.length })}
                  </button>
                  {skipped.some((r) => r.reason === 'duplicate_sessions') && (
                    <p className="mt-1 text-xs font-semibold text-red-400">
                      {t('reconcileAttach.duplicateWarning', {
                        defaultValue:
                          '{{count}} site(s) refused: the concentrator lists several live sessions for their account (see below).',
                        count: skipped.filter((r) => r.reason === 'duplicate_sessions').length,
                      })}
                    </p>
                  )}
                  {showSkipped && (
                    <div className="mt-2 max-h-60 overflow-auto rounded-md border border-border">
                      <table className="w-full">
                        <tbody>
                          {skipped.map((r) => (
                            <tr key={r.siteId} className="border-t border-border first:border-t-0">
                              <SiteCell row={r} />
                              <td className={`${TD} text-xs text-text-muted`}>
                                {reasonText(r.reason)} <DeviceLink d={r.device} />
                                <DuplicateSessions sessions={r.duplicateSessions} />
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  )}
                </div>
              )}

              {/* ── The SSH credential ─────────────────────────────────── */}
              {eligible.length > 0 && (
                <div>
                  <h3 className="mb-1 text-sm font-semibold text-text-primary">
                    {t('reconcileAttach.credentials.title', { defaultValue: 'SSH credential' })}
                  </h3>
                  <p className="mb-2 text-xs text-text-muted">
                    {t('reconcileAttach.credentials.hint', {
                      defaultValue: 'Leave empty = admin + the vault password (admin_password, resolved per site).',
                    })}
                  </p>
                  <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
                    <Input
                      id="attach-username"
                      label={t('reconcileAttach.credentials.username', { defaultValue: 'Username' })}
                      value={username}
                      autoComplete="off"
                      placeholder="admin"
                      onChange={(e) => setUsername(e.target.value)}
                    />
                    <Input
                      id="attach-password"
                      type="password"
                      label={t('reconcileAttach.credentials.password', { defaultValue: 'Password' })}
                      value={password}
                      autoComplete="new-password"
                      onChange={(e) => setPassword(e.target.value)}
                    />
                  </div>
                  {incomplete && (
                    <p className="mt-1 text-xs text-status-down">
                      {t('reconcileAttach.credentials.incomplete', { defaultValue: 'Fill in both fields, or neither.' })}
                    </p>
                  )}
                  {selectedNeedingCredential > 0 && (
                    <p className="mt-1 text-xs text-amber-400">
                      {t('reconcileAttach.needsCredential.selected', {
                        defaultValue:
                          '{{count}} selected router(s) can be attached only with a credential typed here; without one, the dry run skips them.',
                        count: selectedNeedingCredential,
                      })}
                    </p>
                  )}
                </div>
              )}

              {/* ── What follows the attach ────────────────────────────── */}
              {eligible.length > 0 && (
                <div>
                  <h3 className="mb-1 text-sm font-semibold text-text-primary">
                    {t('reconcileAttach.followUps.title', { defaultValue: 'After the attach' })}
                  </h3>
                  <label className="flex items-start gap-2 text-sm text-text-primary">
                    <input
                      type="checkbox"
                      className="mt-0.5"
                      checked={openManagementAccess}
                      onChange={(e) => setOpenManagementAccess(e.target.checked)}
                    />
                    <span>
                      {t('reconcileAttach.followUps.openManagementAccess', {
                        defaultValue: 'Open management access (obliwan account, API-SSL) after the attach',
                      })}
                    </span>
                  </label>
                  <label className={`mt-1 flex items-start gap-2 pl-5 text-sm ${openManagementAccess ? 'text-text-primary' : 'text-text-muted'}`}>
                    <input
                      type="checkbox"
                      className="mt-0.5"
                      disabled={!openManagementAccess}
                      checked={openManagementAccess && applyComplianceChecked}
                      onChange={(e) => setApplyComplianceChecked(e.target.checked)}
                    />
                    <span>
                      {t('reconcileAttach.followUps.applyCompliance', { defaultValue: 'Then apply the template fixes' })}
                      <span className="block text-xs text-text-muted">
                        {t('reconcileAttach.followUps.applyComplianceHint', {
                          defaultValue: 'Queued by ObliWAN once the management access job has succeeded on the router; never otherwise.',
                        })}
                      </span>
                    </span>
                  </label>
                  <label className="mt-1 flex items-start gap-2 text-sm text-text-primary">
                    <input
                      type="checkbox"
                      className="mt-0.5"
                      checked={putInLearning}
                      onChange={(e) => setPutInLearning(e.target.checked)}
                    />
                    <span>
                      {t('reconcileAttach.learning.checkbox', { defaultValue: 'Put in learning mode' })}
                      <span className="block text-xs text-text-muted">
                        {t('reconcileAttach.learning.hint', {
                          defaultValue:
                            'Each attached router is put in learning mode (template pushes refused; management access and template fixes still run), then one learning capture is started for them.',
                        })}
                      </span>
                    </span>
                  </label>
                  <p className="mt-1 text-xs text-text-muted">
                    {t('reconcileAttach.followUps.scope', {
                      defaultValue:
                        'These follow-ups apply to the routers attached now. For routers already attached, use Rollouts ' +
                        '(management access, then template fixes) or each device page.',
                    })}
                  </p>
                  {needsConfirmation && (
                    <label className="mt-2 flex items-start gap-2 rounded-md border border-status-ssl-warning/50 bg-status-ssl-warning/5 p-3 text-[12px] text-text-secondary">
                      <input
                        type="checkbox"
                        className="mt-0.5"
                        checked={confirmNoDeadman}
                        onChange={(e) => setConfirmNoDeadman(e.target.checked)}
                      />
                      <span>
                        {t('reconcileAttach.followUps.confirm', {
                          defaultValue:
                            'I confirm the degraded safety level of these jobs, for the whole batch: no dead-man is armed. ' +
                            'Management access only writes /certificate, the api-ssl service and, when missing, ObliWAN\'s own ' +
                            '"obliwan" group and user — and, the one existing account or group it changes, adds the "sensitive" policy to an ' +
                            '"obliwan" group ObliWAN made earlier when it is the only policy that group lacks — then switches ' +
                            'ObliWAN to that account once a login with it is proven; the ' +
                            'template fixes only open mac-server, mac-winbox and RoMON, add the DNS-Amp rules and add the store ' +
                            'LAN to the ssh and winbox lists. Each job pulls a pre-change backup first; without one nothing is written.',
                        })}
                      </span>
                    </label>
                  )}
                </div>
              )}

              {/* ── The dry run ────────────────────────────────────────── */}
              {dry && dryCurrent && (
                <div>
                  <h3 className="mb-2 text-sm font-semibold text-text-primary">
                    {t('reconcileAttach.dry.title', {
                      defaultValue: 'Dry run: {{eligible}} to attach, {{skipped}} skipped',
                      eligible: dry.preview.counts.eligible,
                      skipped: dry.preview.counts.skipped,
                    })}
                  </h3>
                  <div className="max-h-72 overflow-auto rounded-md border border-border">
                    <table className="w-full">
                      <tbody>
                        {dry.preview.rows.map((r) => (
                          <tr key={r.siteId} className="border-t border-border first:border-t-0">
                            <SiteCell row={r} />
                            <td className={`${TD} text-xs`}>
                              {r.verdict === 'eligible' ? (
                                <span className="text-text-primary">
                                  {t('reconcileAttach.dry.willAttach', {
                                    defaultValue: 'will be proven then attached — SSH {{user}}@{{address}}',
                                    user: r.sshUsername,
                                    address: r.tunnelIp,
                                  })}
                                  <span className="ml-1 text-text-muted">({scopeText(r)})</span>
                                  {r.followUps.map((p) => (
                                    <span
                                      key={p.kind}
                                      className={`block text-[11px] ${p.plan === 'refused' ? 'text-amber-400' : 'text-text-muted'}`}
                                    >
                                      {planText(p)}
                                    </span>
                                  ))}
                                </span>
                              ) : (
                                <span className="text-text-muted">
                                  {t('reconcileAttach.result.skipped', { defaultValue: 'Skipped' })}: {reasonText(r.reason)}{' '}
                                  <DeviceLink d={r.device} />
                                  <DuplicateSessions sessions={r.duplicateSessions} />
                                </span>
                              )}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                  {sharedPasswordCount > 0 && (
                    <p className="mt-2 text-xs text-amber-400">
                      {t('reconcileAttach.dry.sharedPassword', {
                        defaultValue:
                          "{{count}} router(s) will log in with the INSTANCE-level admin_password, shared by every workspace. A copy will be stored, encrypted, on these devices of this workspace, where its users who may reveal or manage credentials can recover it. Type the credential above instead to avoid storing the shared one.",
                        count: sharedPasswordCount,
                      })}
                    </p>
                  )}
                </div>
              )}
              {dry && !dryCurrent && (
                <p className="text-xs text-amber-400">
                  {t('reconcileAttach.dry.stale', {
                    defaultValue: 'The selection or the credential changed: run the dry run again.',
                  })}
                </p>
              )}
            </>
          )}

          {/* ── Results ──────────────────────────────────────────────── */}
          {results !== null && (
            <div>
              <h3 className="mb-2 text-sm font-semibold text-text-primary">
                {busy === 'apply' && progress
                  ? t('reconcileAttach.applying', { defaultValue: 'Attaching… {{done}}/{{total}}', ...progress })
                  : counts &&
                    t('reconcileAttach.summary', {
                      defaultValue: '{{attached}} attached, {{failed}} not attached, {{skipped}} skipped',
                      ...counts,
                    })}
              </h3>
              {learningOutcome && (
                <div className="mb-2 text-xs">
                  <div className="text-text-primary">
                    {t('reconcileAttach.learning.enabled', {
                      defaultValue: '{{count}} router(s) put in learning mode.',
                      count: learningOutcome.enabled,
                    })}{' '}
                    {learningOutcome.capture &&
                      ('total' in learningOutcome.capture
                        ? t('reconcileAttach.learning.captureStarted', {
                            defaultValue: 'Learning capture started for {{count}} router(s).',
                            count: learningOutcome.capture.total,
                          })
                        : null)}
                  </div>
                  {learningOutcome.capture && 'error' in learningOutcome.capture && (
                    <div className="text-amber-400">
                      {t('reconcileAttach.learning.captureFailed', {
                        defaultValue: 'The learning capture could not be started (start it from the Learning page): {{error}}',
                        error: learningOutcome.capture.error,
                      })}
                    </div>
                  )}
                  {learningOutcome.errors.map((e, i) => (
                    <div key={i} className="text-amber-400">
                      {t('reconcileAttach.learning.failed', { defaultValue: 'Learning mode not set: {{error}}', error: e })}
                    </div>
                  ))}
                </div>
              )}
              <div className="max-h-96 overflow-auto rounded-md border border-border">
                <table className="w-full">
                  <thead>
                    <tr>
                      <th className={TH}>{t('reconcileAttach.col.site', { defaultValue: 'Site' })}</th>
                      <th className={TH}>{t('reconcileAttach.col.result', { defaultValue: 'Result' })}</th>
                      <th className={TH}>{t('reconcileAttach.col.device', { defaultValue: 'Device' })}</th>
                    </tr>
                  </thead>
                  <tbody>
                    {results.map((r) => (
                      <tr key={r.siteId} className="border-t border-border">
                        <SiteCell row={r} />
                        <td className={`${TD} text-xs`}>
                          {r.outcome === 'attached' ? (
                            <span className="flex items-center gap-1 text-green-400">
                              <CheckCircle2 size={14} /> {t('reconcileAttach.result.attached', { defaultValue: 'Attached and proven' })}
                            </span>
                          ) : r.outcome === 'failed' ? (
                            <span className="flex items-center gap-1 text-status-down">
                              <XCircle size={14} /> {t('reconcileAttach.result.failed', { defaultValue: 'Not attached (nothing created)' })}:{' '}
                              {reasonText(r.reason)}
                            </span>
                          ) : (
                            <span className="flex items-center gap-1 text-text-muted">
                              <MinusCircle size={14} /> {t('reconcileAttach.result.skipped', { defaultValue: 'Skipped' })}:{' '}
                              {reasonText(r.reason)}
                            </span>
                          )}
                          {r.detail && <div className="mt-0.5 font-mono text-[11px] text-text-muted">{r.detail}</div>}
                          <DuplicateSessions sessions={r.duplicateSessions} />
                          {r.facts && r.outcome === 'attached' && (
                            <div className="mt-0.5 text-[11px] text-text-muted">
                              {[r.facts.systemIdentity, r.facts.model, r.facts.serial, r.facts.osVersion && `RouterOS ${r.facts.osVersion}`]
                                .filter(Boolean)
                                .join(' · ')}
                            </div>
                          )}
                          {r.outcome === 'attached' &&
                            r.followUps.map((f) => (
                              <div
                                key={f.kind}
                                className={`mt-0.5 text-[11px] ${
                                  f.status === 'refused' || f.status === 'skipped' ? 'text-amber-400' : 'text-text-muted'
                                }`}
                              >
                                {resultText(f)}
                              </div>
                            ))}
                        </td>
                        <td className={TD}>
                          <DeviceLink d={r.device} />
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {error && <p className="text-sm text-status-down">{error}</p>}
        </div>

        <div className="flex flex-wrap items-center justify-end gap-2 border-t border-border px-5 py-3">
          {results === null ? (
            <>
              <span className="mr-auto text-xs text-text-muted">
                {t('reconcileAttach.dry.help', { defaultValue: 'The dry run dials nothing: it says, per site, what the attach will do.' })}
              </span>
              <Button size="sm" variant="secondary" onClick={onClose}>
                {t('reconcileAttach.cancel', { defaultValue: 'Cancel' })}
              </Button>
              <Button
                size="sm"
                variant="secondary"
                onClick={() => void runDry()}
                loading={busy === 'dry'}
                disabled={busy !== null || selection.length === 0 || incomplete}
              >
                {t('reconcileAttach.dry.run', { defaultValue: 'Dry run' })}
              </Button>
              {needsConfirmation && !confirmNoDeadman && toApply.length > 0 && (
                <span className="text-xs text-amber-400">
                  {t('reconcileAttach.followUps.confirmNeeded', {
                    defaultValue: 'Tick the confirmation, or untick the follow-up jobs.',
                  })}
                </span>
              )}
              <Button
                size="sm"
                onClick={() => void apply()}
                disabled={busy !== null || toApply.length === 0 || (needsConfirmation && !confirmNoDeadman)}
              >
                {t('reconcileAttach.apply', { defaultValue: 'Attach {{count}} router(s)', count: toApply.length })}
              </Button>
            </>
          ) : (
            <Button size="sm" onClick={onClose} disabled={busy === 'apply'}>
              {t('reconcileAttach.close', { defaultValue: 'Close' })}
            </Button>
          )}
        </div>
      </div>
    </div>
  );
}

export default AttachDevicesDialog;
