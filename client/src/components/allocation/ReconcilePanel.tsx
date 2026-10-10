import { Fragment, useCallback, useEffect, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import toast from 'react-hot-toast';
import { ChevronDown, ChevronRight, Download, Plus, RefreshCw } from 'lucide-react';
import { Button } from '@/components/common/Button';
import {
  allocationApi,
  allocationError,
  type ChrAccount,
  type NearReason,
  type ReconcileBlocker,
  type ReconcileHolder,
  type ReconcileNearSite,
  type ReconcileOffPattern,
  type ReconcileOrphan,
  type ReconcileReport,
} from '@/api/allocation.api';

/**
 * CHR <-> sites reconciliation of one tenant (server: reconcile.service.ts).
 *
 * Answers, before a batch of live stores is entered: which L2TP accounts of
 * this tenant have no site (orphans — a router online is a store in
 * production), and which sites will find no account (new, or SUSPECT when a
 * live account names the same store differently — allocating such a site
 * would create a second address, then a second CHR account). When the
 * template misses the CHR's naming altogether, the off-pattern and
 * unexplained accounts are what show it.
 *
 * Reading it changes nothing. Two buttons do write, each saying what: "Re-read
 * the CHR" (its /ppp/secret, nothing written to the router) and "Create the
 * site" (one site in THIS tenant, whatever tenant the session is on, with the
 * country read from the account; nothing allocated). "Orphans to import"
 * writes nothing: it downloads the orphans in the site import's own columns,
 * for the bulk round trip through the ordinary import (whose tenant is the
 * session's — the help line says so).
 *
 * The page mounts one panel per tenant (`key`), and every answer is still
 * checked against the tenant it was asked for: a report, or a site creation,
 * can never land under another tenant than the one on screen.
 */

const INPUT =
  'w-full rounded-lg border border-border bg-bg-primary px-2 py-1 text-sm text-text-primary ' +
  'focus:outline-none focus:ring-1 focus:ring-accent';
const CARD = 'mb-4 rounded-xl border border-border bg-bg-secondary p-4';
const TH = 'px-2 py-1.5 text-left text-xs font-medium text-text-muted';
const TD = 'px-2 py-1.5 text-sm text-text-primary align-top';
const CHIP = 'rounded bg-bg-primary px-1.5 py-0.5 text-xs';

interface Props {
  tenantId: number;
  tenantName: string;
  /** Changes whenever the stored policy changes; the report is then recomputed. */
  policyStamp: string | null;
  hasPolicy: boolean;
  /** The policy form differs from the stored policy, which is what the report reads. */
  unsaved: boolean;
}

interface CreateDraft {
  /** The tenant the orphan was reported for: the only one it may be created in. */
  tenantId: number;
  key: string;
  code: string;
  name: string;
  country: string;
  nearSites: ReconcileNearSite[];
  creationAdopts: boolean;
  blockers: ReconcileBlocker[];
  /** The template names no tenant: the account may be another customer's. */
  ownershipUnproven: boolean;
}

function accountKey(a: ChrAccount): string {
  return `${a.concentratorId}:${a.name}`;
}

export function ReconcilePanel({ tenantId, tenantName, policyStamp, hasPolicy, unsaved }: Props) {
  const { t, i18n } = useTranslation();
  const [report, setReport] = useState<ReconcileReport | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [rereading, setRereading] = useState<number | null>(null);
  const [open, setOpen] = useState({ orphans: true, siteOnly: true, matched: false, offPattern: false, unexplained: false });
  const [draft, setDraft] = useState<CreateDraft | null>(null);
  const [draftErrors, setDraftErrors] = useState<Record<string, string[]>>({});
  const [saving, setSaving] = useState(false);

  // The tenant on screen now, read after every await. Synced before the load
  // effect below runs (effects run in order).
  const currentTenant = useRef(tenantId);
  useEffect(() => {
    currentTenant.current = tenantId;
  }, [tenantId]);
  // Only the latest request may fill the panel.
  const latest = useRef(0);
  const load = useCallback(async () => {
    const forTenant = tenantId;
    const ticket = ++latest.current;
    setLoading(true);
    setError(null);
    try {
      const r = await allocationApi.reconcile(forTenant);
      if (ticket === latest.current && currentTenant.current === forTenant && r.tenantId === forTenant) setReport(r);
    } catch (err) {
      if (ticket === latest.current && currentTenant.current === forTenant) {
        setReport(null);
        setError(allocationError(err).message);
      }
    } finally {
      if (ticket === latest.current) setLoading(false);
    }
  }, [tenantId]);

  useEffect(() => {
    latest.current += 1;
    setReport(null);
    setError(null);
    setLoading(false);
    setDraft(null);
    if (hasPolicy) void load();
  }, [load, hasPolicy, policyStamp]);

  // Never draw another tenant's report, whatever reached the state.
  const shown = report !== null && report.tenantId === tenantId ? report : null;

  const fmt = (iso: string | null): string => (iso ? new Date(iso).toLocaleString(i18n.language) : '—');

  const reread = async (concentratorId: number) => {
    const forTenant = tenantId;
    setRereading(concentratorId);
    try {
      const r = await allocationApi.rereadConcentrator(concentratorId);
      toast.success(
        t('allocation.reconcile.rereadDone', {
          defaultValue: '{{count}} accounts read on the CHR ({{vanished}} gone since the last read)',
          count: r.recorded,
          vanished: r.vanished,
        }),
      );
      if (currentTenant.current === forTenant) await load();
    } catch (err) {
      toast.error(allocationError(err).message);
    } finally {
      setRereading(null);
    }
  };

  const startCreate = (o: ReconcileOrphan, namesTenant: boolean) => {
    setDraftErrors({});
    const code = o.prefill.code ?? '';
    setDraft({
      tenantId,
      key: accountKey(o.account),
      code,
      name:
        o.prefill.name ??
        t('allocation.reconcile.create.defaultName', { defaultValue: 'Site {{code}}', code: code || '?' }),
      country: o.prefill.country ?? '',
      nearSites: o.nearSites,
      creationAdopts: o.creationAdopts,
      blockers: o.blockers,
      ownershipUnproven: !namesTenant,
    });
  };

  const blockerText = (b: ReconcileBlocker) =>
    t(`allocation.reconcile.blocker.${b}`, {
      defaultValue: {
        ambiguous: 'several spellings on the CHR',
        noAddress: 'no fixed remote-address',
        sessionOnly: 'no /ppp/secret entry',
        otherTenant: 'login held by another tenant',
        sharedLogin: 'another site has the same login',
        loginTaken: 'login held elsewhere',
        addressTaken: 'address held elsewhere',
        addressInLan: "address inside a site's LAN",
        foreignPool: "address in another tenant's plan",
        profileInvalid: 'PPP profile an allocation cannot store',
        otherConcentrator: "on another CHR than the policy's",
      }[b],
    });

  const submitCreate = async () => {
    if (!draft) return;
    // The draft was made from THIS tenant's report; anything else is refused.
    if (draft.tenantId !== tenantId) {
      setDraft(null);
      return;
    }
    const warnings: string[] = [];
    if (draft.ownershipUnproven) {
      warnings.push(
        t('allocation.reconcile.create.confirmUnproven', {
          defaultValue:
            "This tenant's login template does not name the tenant: this account may belong to another customer of the same CHR.",
        }),
      );
    }
    if (!draft.creationAdopts) {
      warnings.push(
        t('allocation.reconcile.create.confirmWontAdopt', {
          defaultValue:
            'Its allocation would NOT take this account over ({{why}}): the site would get a new address, then a second CHR account for a store that may already be live.',
          why: draft.blockers.length > 0 ? draft.blockers.map(blockerText).join(', ') : '—',
        }),
      );
    }
    if (draft.nearSites.length > 0) {
      warnings.push(
        t('allocation.reconcile.create.confirmNear', {
          defaultValue: 'This account resembles existing site(s) {{sites}}: correcting that site is usually the right fix.',
          sites: draft.nearSites.map((s) => s.code).join(', '),
        }),
      );
    }
    if (
      warnings.length > 0 &&
      !confirm(
        `${warnings.join('\n\n')}\n\n${t('allocation.reconcile.create.confirmAnyway', {
          defaultValue: 'Create the site in {{tenant}} anyway?',
          tenant: tenantName,
        })}`,
      )
    ) {
      return;
    }
    const forTenant = draft.tenantId;
    setSaving(true);
    setDraftErrors({});
    try {
      const site = await allocationApi.createReconciledSite(forTenant, {
        code: draft.code.trim(),
        name: draft.name.trim(),
        country: draft.country.trim() === '' ? null : draft.country.trim(),
      });
      toast.success(
        t('allocation.reconcile.create.done', {
          defaultValue: 'Site {{code}} created in {{tenant}}.',
          code: site.code,
          tenant: tenantName,
        }),
      );
      if (currentTenant.current === forTenant) {
        setDraft(null);
        await load();
      }
    } catch (err) {
      const e = allocationError(err);
      if (currentTenant.current === forTenant) setDraftErrors(e.details);
      toast.error(e.message);
    } finally {
      setSaving(false);
    }
  };

  const reasonText = (r: NearReason) =>
    t(`allocation.reconcile.reason.${r}`, {
      defaultValue: {
        country: 'country',
        prefix: 'prefix',
        zeros: 'leading zeros',
        separator: 'separator',
        name: 'name',
        template: 'fixed part differs',
        device: 'router of the site',
      }[r],
    });

  const holderText = (h: ReconcileHolder): string => {
    const base =
      h.kind === 'lan'
        ? t('allocation.reconcile.holder.lan', { defaultValue: 'LAN {{detail}} of site {{name}}', name: h.name, detail: h.detail ?? '' })
        : h.kind === 'site'
          ? t('allocation.reconcile.holder.site', { defaultValue: 'site {{name}}', name: h.name })
          : h.kind === 'device'
            ? t('allocation.reconcile.holder.device', { defaultValue: 'router {{name}}', name: h.name })
            : h.kind === 'session'
              ? t('allocation.reconcile.holder.session', {
                  defaultValue: 'session {{name}} (CHR #{{detail}})',
                  name: h.name,
                  detail: h.detail ?? '?',
                })
              : t('allocation.reconcile.holder.secret', {
                  defaultValue: 'CHR account {{name}} (CHR #{{detail}})',
                  name: h.name,
                  detail: h.detail ?? '?',
                });
    return h.tenantSlug ? `${base} [${h.tenantSlug}]` : base;
  };

  const Reasons = ({ reasons }: { reasons: NearReason[] }) => (
    <>
      {reasons.map((r) => (
        <span key={r} className="ml-1 whitespace-nowrap rounded bg-amber-500/15 px-1.5 py-0.5 text-xs text-amber-400">
          {reasonText(r)}
        </span>
      ))}
    </>
  );

  const Blockers = ({ blockers, holders }: { blockers: ReconcileBlocker[]; holders: ReconcileHolder[] }) =>
    blockers.length === 0 ? null : (
      <div className="mt-0.5 text-xs text-amber-400">
        {blockers.map(blockerText).join(' · ')}
        {holders.length > 0 && (
          <div className="text-text-muted">
            {t('allocation.reconcile.heldBy', { defaultValue: 'held by: {{list}}', list: holders.map(holderText).join(', ') })}
          </div>
        )}
      </div>
    );

  const Session = ({ a }: { a: ChrAccount }) => (
    <div className="text-xs">
      {a.session.up ? (
        <span
          className="text-green-400"
          title={t('allocation.reconcile.session.upHelp', {
            defaultValue: "First seen by ObliWAN's presence, not the moment the router dialled.",
          })}
        >
          {t('allocation.reconcile.session.up', { defaultValue: 'seen online since {{date}}', date: fmt(a.session.since) })}
        </span>
      ) : a.session.lastEndedAt ? (
        <span className="text-text-muted">
          {t('allocation.reconcile.session.down', {
            defaultValue: 'offline since {{date}}',
            date: fmt(a.session.lastEndedAt),
          })}
        </span>
      ) : (
        <span className="text-text-muted">
          {t('allocation.reconcile.session.never', { defaultValue: 'never seen online' })}
        </span>
      )}
    </div>
  );

  const AccountCell = ({ a }: { a: ChrAccount }) => (
    <div>
      <span className="font-mono">{a.name}</span>
      {!a.declared && (
        <span className="ml-1 text-xs text-amber-400">
          ({t('allocation.reconcile.notDeclared', { defaultValue: 'session without a secret' })})
        </span>
      )}
      {a.disabled === true && (
        <span className="ml-1 text-xs text-text-muted">
          ({t('allocation.reconcile.disabledShort', { defaultValue: 'disabled' })})
        </span>
      )}
      {a.device && (
        <div className="text-xs text-text-muted">
          {t('allocation.reconcile.device', { defaultValue: 'router {{name}}', name: a.device.name })}
        </div>
      )}
    </div>
  );

  const NearSites = ({ sites }: { sites: ReconcileNearSite[] }) =>
    sites.length === 0 ? (
      <span className="text-text-muted">—</span>
    ) : (
      <>
        {sites.map((s) => (
          <div key={s.siteId} className="text-amber-400">
            <span className="font-mono">{s.code}</span> {s.name}
            <Reasons reasons={s.reasons} />
          </div>
        ))}
      </>
    );

  const viaText = (via: ReconcileOffPattern['via']) =>
    t(`allocation.reconcile.via.${via}`, {
      defaultValue: {
        anchor: "carries the tenant's fixed part",
        slug: "contains the tenant's name",
        device: 'a router of this tenant dials it',
      }[via],
    });

  const Toggle = ({ k, title, count }: { k: keyof typeof open; title: string; count: number }) => (
    <button
      type="button"
      className="mb-2 flex items-center gap-1 text-sm font-semibold text-text-primary"
      onClick={() => setOpen((o) => ({ ...o, [k]: !o[k] }))}
    >
      {open[k] ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
      {title} ({count})
    </button>
  );

  const policyChr = shown?.inventory.find((i) => i.policy) ?? null;
  const drift =
    shown !== null &&
    shown.counts.sites > 0 &&
    shown.counts.matched === 0 &&
    (shown.counts.offPattern > 0 || shown.counts.unexplainedOnline > 0);

  return (
    <div className={CARD}>
      <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
        <h2 className="text-sm font-semibold text-text-primary">
          {t('allocation.reconcile.title', { defaultValue: 'CHR ↔ sites reconciliation' })}
        </h2>
        <div className="flex gap-2">
          <Button size="sm" variant="secondary" onClick={() => void load()} disabled={!hasPolicy} loading={loading}>
            <RefreshCw size={14} /> {t('allocation.reconcile.refresh', { defaultValue: 'Refresh' })}
          </Button>
          {shown && (
            <a href={allocationApi.reconcileXlsxUrl(tenantId)}>
              <Button size="sm" variant="secondary">
                <Download size={14} /> {t('allocation.reconcile.export', { defaultValue: 'Export (Excel)' })}
              </Button>
            </a>
          )}
          {shown && shown.orphans.length > 0 && (
            <a
              href={allocationApi.reconcileOrphansXlsxUrl(tenantId)}
              onClick={(e) => {
                if (
                  !shown.pattern.namesTenant &&
                  !confirm(
                    t('allocation.reconcile.orphans.exportUnproven', {
                      defaultValue:
                        "This tenant's login template does not name the tenant: on a CHR shared with other customers, an orphan it reads may be theirs. Check each row before importing it. Export anyway?",
                    }),
                  )
                ) {
                  e.preventDefault();
                }
              }}
            >
              <Button size="sm" variant="secondary">
                <Download size={14} />{' '}
                {t('allocation.reconcile.orphans.export', { defaultValue: 'Orphans to import (Excel)' })}
              </Button>
            </a>
          )}
        </div>
      </div>
      <p className="mb-3 text-xs text-text-muted">
        {t('allocation.reconcile.help', {
          defaultValue:
            "Compares the tenant's sites with the L2TP accounts its concentrator declares, before anything is allocated. Read-only: nothing is allocated, nothing is written to the CHR.",
        })}
      </p>

      {!hasPolicy && (
        <p className="text-sm text-text-muted">
          {t('allocation.reconcile.noPolicy', {
            defaultValue:
              "Save a policy first: without a login template, no CHR account can be recognised as this tenant's.",
          })}
        </p>
      )}
      {hasPolicy && unsaved && (
        <p className="mb-2 text-sm text-amber-400">
          {t('allocation.reconcile.unsaved', {
            defaultValue: 'The policy has unsaved changes: this reconciliation reads the saved policy.',
          })}
        </p>
      )}
      {error && <p className="mb-2 text-sm text-red-400">{error}</p>}
      {loading && !shown && (
        <p className="text-sm text-text-muted">{t('allocation.reconcile.loading', { defaultValue: 'Reading…' })}</p>
      )}

      {shown && (
        <>
          {/* ── What was read, and how ─────────────────────────────────── */}
          <div className="mb-3 grid grid-cols-1 gap-3 md:grid-cols-2">
            <div className="rounded-lg border border-border p-3">
              <div className="text-xs text-text-muted">
                {t('allocation.reconcile.pattern', { defaultValue: 'Login pattern read' })}
              </div>
              <div className="font-mono text-sm text-text-primary">{shown.pattern.display}</div>
              {shown.pattern.captures.includes('country') && (
                <div className="mt-1 text-xs text-text-muted">
                  {t('allocation.reconcile.patternCountry', {
                    defaultValue: '{site.country} is optional: an account without a country is read too.',
                  })}
                </div>
              )}
              <div className="mt-1 text-xs text-text-muted">
                {shown.pattern.anchor === null
                  ? t('allocation.reconcile.anchorNone', {
                      defaultValue:
                        'The fixed part of the template does not name the tenant: near-matches are searched only among accounts it can produce.',
                    })
                  : shown.pattern.anchor.kind === 'suffix'
                    ? t('allocation.reconcile.anchorSuffix', {
                        defaultValue: 'Near-matches are also searched among accounts ending with {{text}}.',
                        text: shown.pattern.anchor.text,
                      })
                    : t('allocation.reconcile.anchorPrefix', {
                        defaultValue: 'Near-matches are also searched among accounts starting with {{text}}.',
                        text: shown.pattern.anchor.text,
                      })}
              </div>
            </div>
            <div className="rounded-lg border border-border p-3">
              <div className="text-xs text-text-muted">
                {t('allocation.reconcile.inventory', { defaultValue: 'CHR inventory' })}
              </div>
              {shown.inventory.map((c) => (
                <div key={c.concentratorId} className="mt-1 flex flex-wrap items-center justify-between gap-2 text-sm">
                  <div>
                    <span className="text-text-primary">{c.name ?? `#${c.concentratorId}`}</span>
                    {c.policy && (
                      <span className={`ml-1 ${CHIP} text-text-muted`}>
                        {t('allocation.reconcile.policyChr', { defaultValue: 'policy CHR' })}
                      </span>
                    )}
                    <div className={`text-xs ${c.readAt === null ? 'text-red-400' : 'text-text-muted'}`}>
                      {c.readAt === null
                        ? t('allocation.reconcile.neverRead', {
                            defaultValue: 'never read: nothing can be reconciled until it is',
                          })
                        : t('allocation.reconcile.readAt', {
                            defaultValue: 'read {{date}} ({{count}} accounts)',
                            date: fmt(c.readAt),
                            count: c.secretCount ?? 0,
                          })}
                    </div>
                    {c.presence.sessionsRecorded === 0 ? (
                      <div className="text-xs text-amber-400">
                        {t('allocation.reconcile.presence.none', {
                          defaultValue:
                            'presence has never recorded a session on this CHR: "never seen online" proves nothing here',
                        })}
                      </div>
                    ) : (
                      <div className="text-xs text-text-muted">
                        {t('allocation.reconcile.presence.line', {
                          defaultValue: 'presence: {{open}} open session(s), last event {{date}}',
                          open: c.presence.openSessions,
                          date: fmt(c.presence.lastEventAt),
                        })}
                      </div>
                    )}
                    {c.presence.degradedSince !== null && (
                      <div className="text-xs text-amber-400">
                        {t('allocation.reconcile.presence.degraded', {
                          defaultValue: 'presence degraded since {{date}}: online states are as they were then',
                          date: fmt(c.presence.degradedSince),
                        })}
                      </div>
                    )}
                  </div>
                  <Button
                    size="sm"
                    variant="ghost"
                    onClick={() => void reread(c.concentratorId)}
                    loading={rereading === c.concentratorId}
                    disabled={rereading !== null}
                  >
                    <RefreshCw size={14} /> {t('allocation.reconcile.rereadButton', { defaultValue: 'Re-read the CHR' })}
                  </Button>
                </div>
              ))}
              <div className="mt-2 text-xs text-text-muted">
                {t('allocation.reconcile.generatedAt', { defaultValue: 'Computed {{date}}', date: fmt(shown.generatedAt) })}
              </div>
            </div>
          </div>

          {/* ── Counts ─────────────────────────────────────────────────── */}
          <div className="mb-3 flex flex-wrap gap-2 text-sm">
            <span className={`${CHIP} text-text-primary`}>
              {t('allocation.reconcile.count.matched', { defaultValue: 'Matched' })}: {shown.counts.matched}
            </span>
            <span className={`${CHIP} ${shown.counts.orphans > 0 ? 'text-amber-400' : 'text-text-primary'}`}>
              {t('allocation.reconcile.count.orphans', { defaultValue: 'CHR accounts without a site' })}:{' '}
              {shown.counts.orphans} ·{' '}
              {t('allocation.reconcile.count.online', { defaultValue: 'online: {{count}}', count: shown.counts.orphansOnline })}
            </span>
            <span className={`${CHIP} ${shown.counts.siteOnlySuspect > 0 ? 'text-red-400' : 'text-text-primary'}`}>
              {t('allocation.reconcile.count.siteOnly', { defaultValue: 'Sites without a CHR account' })}:{' '}
              {shown.counts.siteOnly} ·{' '}
              {t('allocation.reconcile.count.suspect', { defaultValue: 'suspect: {{count}}', count: shown.counts.siteOnlySuspect })}
            </span>
            {shown.counts.offPattern > 0 && (
              <span className={`${CHIP} text-amber-400`}>
                {t('allocation.reconcile.count.offPattern', { defaultValue: 'Off-pattern accounts' })}:{' '}
                {shown.counts.offPattern}
              </span>
            )}
            {shown.counts.unexplained > 0 && (
              <span className={`${CHIP} text-text-muted`}>
                {t('allocation.reconcile.count.unexplained', { defaultValue: 'Accounts no tenant explains' })}:{' '}
                {shown.counts.unexplained} ·{' '}
                {t('allocation.reconcile.count.online', { defaultValue: 'online: {{count}}', count: shown.counts.unexplainedOnline })}
              </span>
            )}
          </div>
          {policyChr && policyChr.readAt === null && (
            <p className="mb-2 text-sm text-red-400">
              {t('allocation.reconcile.neverReadWarning', {
                defaultValue:
                  "The policy CHR's inventory has never been read: every site below shows as without an account. Re-read the CHR first.",
              })}
            </p>
          )}
          {drift && (
            <p className="mb-2 text-sm text-red-400">
              {t('allocation.reconcile.driftWarning', {
                defaultValue:
                  "No site matched, while the CHR carries {{offPattern}} off-pattern account(s) for this tenant and {{online}} online account(s) no tenant explains. If this tenant's stores are already live, its login template does not match the CHR's naming: check it before allocating.",
                offPattern: shown.counts.offPattern,
                online: shown.counts.unexplainedOnline,
              })}
            </p>
          )}
          {shown.counts.excludedOtherTenant + shown.counts.excludedSharedPattern > 0 && (
            <p className="mb-2 text-xs text-text-muted">
              {t('allocation.reconcile.excluded', {
                defaultValue:
                  "{{other}} account(s) that look like this tenant's are held by another tenant, and {{shared}} are produced by another tenant's template too: not listed.",
                other: shown.counts.excludedOtherTenant,
                shared: shown.counts.excludedSharedPattern,
              })}
            </p>
          )}

          {/* ── Orphans ────────────────────────────────────────────────── */}
          <div className="mb-3">
            <Toggle
              k="orphans"
              title={t('allocation.reconcile.orphans.title', { defaultValue: 'CHR accounts without a site (orphans)' })}
              count={shown.orphans.length}
            />
            {open.orphans && (
              <>
                <p className="mb-2 text-xs text-text-muted">
                  {t('allocation.reconcile.orphans.help', {
                    defaultValue:
                      "Accounts this tenant's template produces and no site claims: a store missing from the import, or a closed one. Online = a router in production.",
                  })}
                </p>
                {shown.orphans.length > 0 && (
                  <p className="mb-2 text-xs text-text-muted">
                    {t('allocation.reconcile.orphans.bulkHelp', {
                      defaultValue:
                        'Many at once: "Orphans to import" downloads them in the site import\'s own columns. Fill in the names, save as CSV and import it from the Sites page while working in {{tenant}} — the import creates sites in the tenant your session is on — and its check shows the account each row takes over, re-judged at that moment.',
                      tenant: tenantName,
                    })}
                  </p>
                )}
                {!shown.pattern.namesTenant && shown.orphans.length > 0 && (
                  <p className="mb-2 text-sm text-amber-400">
                    {t('allocation.reconcile.orphans.unproven', {
                      defaultValue:
                        "This tenant's login template does not name the tenant: on a CHR shared with other customers, an account it reads may be theirs. Check each orphan before creating its site.",
                    })}
                  </p>
                )}
                {shown.orphans.length === 0 ? (
                  <p className="text-sm text-text-muted">
                    {t('allocation.reconcile.orphans.none', { defaultValue: 'No orphan account.' })}
                  </p>
                ) : (
                  <div className="overflow-x-auto">
                    <table className="w-full">
                      <thead>
                        <tr>
                          <th className={TH}>{t('allocation.reconcile.col.account', { defaultValue: 'CHR account' })}</th>
                          <th className={TH}>{t('allocation.reconcile.col.readBack', { defaultValue: 'Read back' })}</th>
                          <th className={TH}>{t('allocation.reconcile.col.address', { defaultValue: 'Address' })}</th>
                          <th className={TH}>{t('allocation.reconcile.col.session', { defaultValue: 'Session' })}</th>
                          <th className={TH}>{t('allocation.reconcile.col.near', { defaultValue: 'Resembles' })}</th>
                          <th className={TH} />
                        </tr>
                      </thead>
                      <tbody>
                        {shown.orphans.map((o) => {
                          const key = accountKey(o.account);
                          const editing = draft?.key === key;
                          return (
                            <Fragment key={key}>
                              <tr className={`border-t border-border ${o.account.session.up ? 'bg-green-500/5' : ''}`}>
                                <td className={TD}>
                                  <AccountCell a={o.account} />
                                </td>
                                <td className={`${TD} font-mono`}>
                                  {o.parsed.code ?? (o.parsed.number !== null ? String(o.parsed.number) : o.parsed.slug) ?? '—'}
                                  {o.parsed.country && <span className="ml-1 text-text-muted">({o.parsed.country})</span>}
                                </td>
                                <td className={`${TD} font-mono`}>{o.account.remoteAddress ?? '—'}</td>
                                <td className={TD}>
                                  <Session a={o.account} />
                                </td>
                                <td className={`${TD} text-xs`}>
                                  <NearSites sites={o.nearSites} />
                                </td>
                                <td className={TD}>
                                  <Button
                                    size="sm"
                                    variant="ghost"
                                    onClick={() => startCreate(o, shown.pattern.namesTenant)}
                                    disabled={editing}
                                  >
                                    <Plus size={14} />{' '}
                                    {t('allocation.reconcile.create.button', { defaultValue: 'Create the site' })}
                                  </Button>
                                  {!o.creationAdopts && (
                                    <div className="mt-0.5 text-xs font-semibold text-amber-400">
                                      {t('allocation.reconcile.create.wontAdopt', {
                                        defaultValue: 'its allocation would not take this account over',
                                      })}
                                    </div>
                                  )}
                                  <Blockers blockers={o.blockers} holders={o.holders} />
                                </td>
                              </tr>
                              {editing && draft && (
                                <tr className="border-t border-border bg-bg-primary/40">
                                  <td className={TD} colSpan={6}>
                                    <div className="flex flex-wrap items-end gap-2">
                                      <div className="w-36">
                                        <label className="mb-1 block text-xs text-text-muted">
                                          {t('allocation.reconcile.create.code', { defaultValue: 'Code' })}
                                        </label>
                                        <input
                                          className={`${INPUT} font-mono`}
                                          value={draft.code}
                                          onChange={(e) => setDraft({ ...draft, code: e.target.value })}
                                        />
                                        {draftErrors.code && <p className="mt-1 text-xs text-red-400">{draftErrors.code.join(' ')}</p>}
                                      </div>
                                      <div className="w-64">
                                        <label className="mb-1 block text-xs text-text-muted">
                                          {t('allocation.reconcile.create.name', { defaultValue: 'Name' })}
                                        </label>
                                        <input
                                          className={INPUT}
                                          value={draft.name}
                                          onChange={(e) => setDraft({ ...draft, name: e.target.value })}
                                        />
                                        {draftErrors.name && <p className="mt-1 text-xs text-red-400">{draftErrors.name.join(' ')}</p>}
                                      </div>
                                      <div className="w-20">
                                        <label className="mb-1 block text-xs text-text-muted">
                                          {t('allocation.reconcile.create.country', { defaultValue: 'Country' })}
                                        </label>
                                        <input
                                          className={`${INPUT} font-mono uppercase`}
                                          maxLength={2}
                                          value={draft.country}
                                          onChange={(e) => setDraft({ ...draft, country: e.target.value })}
                                        />
                                        {draftErrors.country && (
                                          <p className="mt-1 text-xs text-red-400">{draftErrors.country.join(' ')}</p>
                                        )}
                                      </div>
                                      <Button size="sm" onClick={() => void submitCreate()} loading={saving}>
                                        {t('allocation.reconcile.create.submit', { defaultValue: 'Create' })}
                                      </Button>
                                      <Button size="sm" variant="ghost" onClick={() => setDraft(null)} disabled={saving}>
                                        {t('allocation.reconcile.create.cancel', { defaultValue: 'Cancel' })}
                                      </Button>
                                    </div>
                                    <p className="mt-1 text-xs text-text-muted">
                                      {t('allocation.reconcile.create.where', {
                                        defaultValue:
                                          'Created in {{tenant}}, whatever tenant your session is on. Nothing is allocated now; the next allocation of the site adopts the account if its login is exactly this one.',
                                        tenant: tenantName,
                                      })}
                                    </p>
                                  </td>
                                </tr>
                              )}
                            </Fragment>
                          );
                        })}
                      </tbody>
                    </table>
                  </div>
                )}
              </>
            )}
          </div>

          {/* ── Sites without an account ───────────────────────────────── */}
          <div className="mb-3">
            <Toggle
              k="siteOnly"
              title={t('allocation.reconcile.siteOnly.title', { defaultValue: 'Sites without a CHR account' })}
              count={shown.siteOnly.length}
            />
            {open.siteOnly && (
              <>
                <p className="mb-2 text-xs text-text-muted">
                  {t('allocation.reconcile.siteOnly.help', {
                    defaultValue:
                      'A new site is normal. A SUSPECT site resembles a live account spelled differently: allocating it would create a second address, then a second CHR account for the same store. Correct the site (code, country) or the template first.',
                  })}
                </p>
                {shown.siteOnly.length === 0 ? (
                  <p className="text-sm text-text-muted">
                    {t('allocation.reconcile.siteOnly.none', { defaultValue: 'Every site has its CHR account.' })}
                  </p>
                ) : (
                  <div className="overflow-x-auto">
                    <table className="w-full">
                      <thead>
                        <tr>
                          <th className={TH}>{t('allocation.reconcile.col.site', { defaultValue: 'Site' })}</th>
                          <th className={TH}>{t('allocation.reconcile.col.login', { defaultValue: 'Expected login' })}</th>
                          <th className={TH}>{t('allocation.reconcile.col.status', { defaultValue: 'Status' })}</th>
                          <th className={TH}>{t('allocation.reconcile.col.near', { defaultValue: 'Resembles' })}</th>
                        </tr>
                      </thead>
                      <tbody>
                        {shown.siteOnly.map((s) => (
                          <tr
                            key={s.siteId}
                            className={`border-t border-border ${s.kind === 'suspect' ? 'bg-amber-500/10' : ''}`}
                          >
                            <td className={TD}>
                              <span className="font-mono">{s.code}</span> <span className="text-text-muted">{s.name}</span>
                              {s.country && <span className="ml-1 text-xs text-text-muted">({s.country})</span>}
                            </td>
                            <td className={`${TD} font-mono`}>
                              {s.login ?? (
                                <span className="font-sans text-red-400" title={s.loginError?.message}>
                                  {t('allocation.reconcile.loginError', { defaultValue: 'login cannot be computed' })}
                                </span>
                              )}
                            </td>
                            <td className={TD}>
                              {s.kind === 'suspect' ? (
                                <span className="font-semibold text-amber-400">
                                  {t('allocation.reconcile.kind.suspect', { defaultValue: 'suspect' })}
                                </span>
                              ) : (
                                t('allocation.reconcile.kind.new', { defaultValue: 'new' })
                              )}
                              {s.allocation && (
                                <div className="text-xs text-text-muted">
                                  {t('allocation.reconcile.allocatedState', {
                                    defaultValue: 'allocated ({{state}})',
                                    state: t(`allocation.state.${s.allocation.state}`, { defaultValue: s.allocation.state }),
                                  })}
                                </div>
                              )}
                              {s.allocation?.state === 'provisioned' && (
                                <div className="text-xs text-red-400">
                                  {t('allocation.reconcile.provisionedMissing', {
                                    defaultValue: "provisioned, yet absent from the CHR's last read",
                                  })}
                                </div>
                              )}
                            </td>
                            <td className={`${TD} text-xs`}>
                              {s.nearMatches.length === 0 ? (
                                <span className="text-text-muted">—</span>
                              ) : (
                                s.nearMatches.map((n) => (
                                  <div key={accountKey(n.account)} className="text-amber-400">
                                    <span className="font-mono">{n.account.name}</span>
                                    <Reasons reasons={n.reasons} />
                                    <Session a={n.account} />
                                  </div>
                                ))
                              )}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </>
            )}
          </div>

          {/* ── Matched ────────────────────────────────────────────────── */}
          <div className="mb-3">
            <Toggle
              k="matched"
              title={t('allocation.reconcile.matched.title', { defaultValue: 'Matched sites' })}
              count={shown.matched.length}
            />
            {open.matched && (
              <>
                <p className="mb-2 text-xs text-text-muted">
                  {t('allocation.reconcile.matched.help', {
                    defaultValue:
                      'For a site not yet allocated, "adoptable" means no refusal of the allocator\'s adoption is visible here (address, login, pools, profile): its allocation should take this account as it is. The allocation preview remains the verdict.',
                  })}
                </p>
                {shown.matched.length === 0 ? (
                  <p className="text-sm text-text-muted">
                    {t('allocation.reconcile.matched.none', { defaultValue: 'No site matched yet.' })}
                  </p>
                ) : (
                  <div className="overflow-x-auto">
                    <table className="w-full">
                      <thead>
                        <tr>
                          <th className={TH}>{t('allocation.reconcile.col.site', { defaultValue: 'Site' })}</th>
                          <th className={TH}>{t('allocation.reconcile.col.account', { defaultValue: 'CHR account' })}</th>
                          <th className={TH}>{t('allocation.reconcile.col.address', { defaultValue: 'Address' })}</th>
                          <th className={TH}>{t('allocation.reconcile.col.session', { defaultValue: 'Session' })}</th>
                          <th className={TH}>{t('allocation.reconcile.col.status', { defaultValue: 'Status' })}</th>
                        </tr>
                      </thead>
                      <tbody>
                        {shown.matched.map((m) => (
                          <tr key={m.siteId} className="border-t border-border">
                            <td className={TD}>
                              <span className="font-mono">{m.code}</span> <span className="text-text-muted">{m.name}</span>
                            </td>
                            <td className={TD}>
                              <AccountCell a={m.account} />
                              {m.variants.length > 0 && (
                                <div className="text-xs text-amber-400">+ {m.variants.join(', ')}</div>
                              )}
                            </td>
                            <td className={`${TD} font-mono`}>{m.account.remoteAddress ?? '—'}</td>
                            <td className={TD}>
                              <Session a={m.account} />
                            </td>
                            <td className={TD}>
                              {m.status === 'adoptable' && m.blockers.length > 0 ? (
                                <span className="font-semibold text-amber-400">
                                  {t('allocation.reconcile.status.blocked', { defaultValue: 'will not be adopted' })}
                                </span>
                              ) : (
                                t(`allocation.reconcile.status.${m.status}`, {
                                  defaultValue: { allocated: 'allocated', adopted: 'adopted', adoptable: 'adoptable' }[m.status],
                                })
                              )}
                              <Blockers blockers={m.blockers} holders={m.holders} />
                              {m.notes.map((n) => (
                                <div key={n} className="text-xs text-text-muted">
                                  {n === 'caseDiffers'
                                    ? t('allocation.reconcile.note.caseDiffers', {
                                        defaultValue: 'CHR spelling: {{name}}',
                                        name: m.account.name,
                                      })
                                    : n === 'addressDiffers'
                                      ? t('allocation.reconcile.note.addressDiffers', {
                                          defaultValue: 'the CHR declares {{address}}, the allocation {{allocated}}',
                                          address: m.account.remoteAddress ?? '—',
                                          allocated: m.allocation?.tunnelIp ?? '—',
                                        })
                                      : t('allocation.reconcile.note.disabled', { defaultValue: 'disabled on the CHR' })}
                                </div>
                              ))}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </>
            )}
          </div>

          {/* ── Off-pattern accounts ───────────────────────────────────── */}
          {shown.offPattern.length > 0 && (
            <div className="mb-3">
              <Toggle
                k="offPattern"
                title={t('allocation.reconcile.offPattern.title', { defaultValue: 'Off-pattern accounts' })}
                count={shown.offPattern.length}
              />
              {open.offPattern && (
                <>
                  <p className="mb-2 text-xs text-text-muted">
                    {t('allocation.reconcile.offPattern.help', {
                      defaultValue:
                        "Accounts this tenant's template cannot produce, listed because they carry its fixed part, contain its name, or are dialled by one of its routers. Not orphans: if there are many, the template probably does not match the CHR's naming.",
                    })}
                  </p>
                  <div className="overflow-x-auto">
                    <table className="w-full">
                      <thead>
                        <tr>
                          <th className={TH}>{t('allocation.reconcile.col.account', { defaultValue: 'CHR account' })}</th>
                          <th className={TH}>{t('allocation.reconcile.col.why', { defaultValue: 'Why listed' })}</th>
                          <th className={TH}>{t('allocation.reconcile.col.address', { defaultValue: 'Address' })}</th>
                          <th className={TH}>{t('allocation.reconcile.col.session', { defaultValue: 'Session' })}</th>
                          <th className={TH}>{t('allocation.reconcile.col.near', { defaultValue: 'Resembles' })}</th>
                        </tr>
                      </thead>
                      <tbody>
                        {shown.offPattern.map((x) => (
                          <tr key={accountKey(x.account)} className="border-t border-border">
                            <td className={TD}>
                              <AccountCell a={x.account} />
                            </td>
                            <td className={`${TD} text-xs text-text-muted`}>{viaText(x.via)}</td>
                            <td className={`${TD} font-mono`}>{x.account.remoteAddress ?? '—'}</td>
                            <td className={TD}>
                              <Session a={x.account} />
                            </td>
                            <td className={`${TD} text-xs`}>
                              <NearSites sites={x.nearSites} />
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </>
              )}
            </div>
          )}

          {/* ── Accounts no tenant explains ────────────────────────────── */}
          {shown.unexplained.length > 0 && (
            <div>
              <Toggle
                k="unexplained"
                title={t('allocation.reconcile.unexplained.title', { defaultValue: 'CHR accounts no tenant explains' })}
                count={shown.unexplained.length}
              />
              {open.unexplained && (
                <>
                  <p className="mb-2 text-xs text-text-muted">
                    {t('allocation.reconcile.unexplained.help', {
                      defaultValue:
                        "On the CHRs read, accounts that no tenant's template, allocation or router accounts for: another customer's, or this tenant's under a naming its template misses. Online first.",
                    })}
                  </p>
                  <div className="overflow-x-auto">
                    <table className="w-full">
                      <thead>
                        <tr>
                          <th className={TH}>{t('allocation.reconcile.col.account', { defaultValue: 'CHR account' })}</th>
                          <th className={TH}>{t('allocation.reconcile.col.address', { defaultValue: 'Address' })}</th>
                          <th className={TH}>{t('allocation.reconcile.col.session', { defaultValue: 'Session' })}</th>
                        </tr>
                      </thead>
                      <tbody>
                        {shown.unexplained.map((a) => (
                          <tr key={accountKey(a)} className="border-t border-border">
                            <td className={TD}>
                              <AccountCell a={a} />
                            </td>
                            <td className={`${TD} font-mono`}>{a.remoteAddress ?? '—'}</td>
                            <td className={TD}>
                              <Session a={a} />
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </>
              )}
            </div>
          )}
        </>
      )}
    </div>
  );
}

export default ReconcilePanel;
