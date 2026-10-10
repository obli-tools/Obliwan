import { useCallback, useEffect, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Link, useSearchParams } from 'react-router-dom';
import toast from 'react-hot-toast';
import { ChevronDown, ChevronRight, Download, GitMerge, Link2, RefreshCw, ShieldCheck } from 'lucide-react';
import { CAPABILITIES } from '@obliwan/shared';
import { Button } from '@/components/common/Button';
import type { NearReason } from '@/api/allocation.api';
import {
  reconcileApi,
  reconcileError,
  type TenantChrAccount,
  type TenantNearSite,
  type TenantReconcileView,
} from '@/api/reconcile.api';
import { useTenantStore } from '@/store/tenantStore';
import { useAuthStore } from '@/store/authStore';
import { AttachDevicesDialog } from '@/components/reconcile/AttachDevicesDialog';
import { AccessCheckDialog } from '@/components/reconcile/AccessCheckDialog';
import { AccessCheckNightlyCard } from '@/components/reconcile/AccessCheckNightlyCard';
import { GodViewMarker } from '@/components/common/TenantBadge';
import { GodViewTenantFilter } from '@/components/common/GodViewTenantFilter';
import { useGodView, useGodViewStore } from '@/store/godViewStore';

/**
 * The CHR <-> sites reconciliation of the workspace the session is on
 * (RECONCILE_READ — the account manager's "view + re-read"). Server:
 * `/api/reconcile`, which reads the tenant off the session and answers a
 * REDACTED report: this workspace's sites and the concentrator accounts the
 * report attributes to it, never another customer's, and no address, pool,
 * profile or concentrator identity.
 *
 * The server REFUSES it (409 TEMPLATE_NAMES_NO_TENANT) when the workspace's
 * login rule does not name the workspace: such a rule reads every customer's
 * accounts on a shared concentrator. The page then says why, and that only a
 * platform administrator can reconcile it.
 *
 * Two buttons act, each saying what: "Re-read the CHR" (its /ppp/secret —
 * nothing is written to the router) and "Orphans to import", a download the
 * site import reads back as it is. Creating the sites goes through the
 * ordinary import (Sites page), whose check shows the account each row takes
 * over.
 *
 * A third, "Attach the online routers", is shown to PLATFORM ADMINISTRATORS
 * only (the server's guard on `/reconcile/attach-devices`: requireRole
 * ('admin'), DEVICE_WRITE and CREDENTIAL_MANAGE declared beside it — the act
 * binds logins of the shared concentrator to devices, which no tenant role
 * may do): it opens AttachDevicesDialog, which turns the matched, allocated,
 * online sites into devices after an SSH proof each.
 *
 * A fourth, "Verify management access and compliance", is shown to callers
 * holding CHANGE_APPLY (the server narrows it to the routers their teams grant
 * `rw` on): it opens AccessCheckDialog — a read-only verification of every
 * router of the workspace, then, on an explicit confirmation, the re-apply of
 * the management access / template-fix jobs where they are needed. Above the
 * report, AccessCheckNightlyCard shows the latest verification (the night's or
 * an operator's), the nightly settings with a link to them, and the open
 * alerts by cause; the alerts link here with `?accessCheck=1`, which opens the
 * verification.
 */

const CARD = 'mb-4 rounded-xl border border-border bg-bg-secondary p-4';
const TH = 'px-2 py-1.5 text-left text-xs font-medium text-text-muted';
const TD = 'px-2 py-1.5 text-sm text-text-primary align-top';
const CHIP = 'rounded bg-bg-primary px-1.5 py-0.5 text-xs';

export function ReconcilePage() {
  const { t, i18n } = useTranslation();
  const currentTenantId = useTenantStore((s) => s.currentTenantId);
  const [view, setView] = useState<TenantReconcileView | null>(null);
  const [refusal, setRefusal] = useState<{ reason: string | null; message: string } | null>(null);
  const [loading, setLoading] = useState(false);
  const [rereading, setRereading] = useState(false);
  const [open, setOpen] = useState({ duplicates: true, orphans: true, siteOnly: true, matched: false, offPattern: false });
  // The whole store, as DevicesPage reads it: `hasCapability` reads the user
  // and permissions inside, so selecting the function alone would not
  // re-render when they load.
  const { hasCapability, isAdmin } = useAuthStore();
  // The server's guard as it stands: the platform role, then the two
  // capabilities (which a platform administrator always holds).
  const canAttach = isAdmin() && hasCapability(CAPABILITIES.DEVICE_WRITE) && hasCapability(CAPABILITIES.CREDENTIAL_MANAGE);
  const [attachOpen, setAttachOpen] = useState(false);
  // "Verify management access and compliance" (server: CHANGE_APPLY, narrowed
  // to the routers the caller's teams grant `rw` on).
  const canAccessCheck = hasCapability(CAPABILITIES.CHANGE_APPLY);
  const [accessCheckOpen, setAccessCheckOpen] = useState(false);
  // The card reads again once the dialog closes.
  const [accessCheckClosed, setAccessCheckClosed] = useState(0);
  // An alert of the nightly verification links here with `?accessCheck=1`:
  // the verification opens, and the parameter goes (a reload does not reopen).
  const [searchParams, setSearchParams] = useSearchParams();
  useEffect(() => {
    if (searchParams.get('accessCheck') === null) return;
    if (canAccessCheck) setAccessCheckOpen(true);
    const next = new URLSearchParams(searchParams);
    next.delete('accessCheck');
    setSearchParams(next, { replace: true });
  }, [searchParams, setSearchParams, canAccessCheck]);
  // God view (store/godViewStore.ts): the reconciliation is ONE workspace's
  // report; the god view picks it with the workspace filter.
  const godView = useGodView();
  const godViewTenant = useGodViewStore((s) => s.filterTenantId);

  // Only the latest request may fill the page (a workspace switch reloads).
  const latest = useRef(0);
  const load = useCallback(async () => {
    const ticket = ++latest.current;
    setLoading(true);
    try {
      const v = await reconcileApi.view();
      if (ticket === latest.current) {
        setView(v);
        setRefusal(null);
      }
    } catch (err) {
      if (ticket === latest.current) {
        const e = reconcileError(err);
        setView(null);
        setRefusal({ reason: e.reason, message: e.message });
      }
    } finally {
      if (ticket === latest.current) setLoading(false);
    }
  }, []);

  useEffect(() => {
    setView(null);
    setRefusal(null);
    void load();
  }, [load, currentTenantId]);

  const reread = async () => {
    const ticket = ++latest.current;
    setRereading(true);
    try {
      const v = await reconcileApi.reread();
      if (ticket === latest.current) {
        setView(v);
        setRefusal(null);
      }
      toast.success(t('reconcile.rereadDone', { defaultValue: 'The concentrator was read again.' }));
    } catch (err) {
      toast.error(reconcileError(err).message);
    } finally {
      setRereading(false);
    }
  };

  const fmt = (iso: string | null): string => (iso ? new Date(iso).toLocaleString(i18n.language) : '—');

  const refusalText = (r: { reason: string | null; message: string }): string =>
    r.reason === 'TEMPLATE_NAMES_NO_TENANT'
      ? t('reconcile.refused.namesNoTenant', {
          defaultValue:
            "This workspace's PPP login rule does not name the workspace: on a concentrator several customers share, the accounts it matches may belong to other customers, so comparing them with your sites would show you other customers' stores. Only a platform administrator can reconcile this workspace.",
        })
      : r.reason === 'NO_POLICY'
        ? t('reconcile.refused.noPolicy', {
            defaultValue:
              'No address allocation policy is set for this workspace, so no concentrator account can be recognised as its own. A platform administrator sets the policy first.',
          })
        : r.message;

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

  const Reasons = ({ reasons }: { reasons: NearReason[] }) => (
    <>
      {reasons.map((r) => (
        <span key={r} className="ml-1 whitespace-nowrap rounded bg-amber-500/15 px-1.5 py-0.5 text-xs text-amber-400">
          {reasonText(r)}
        </span>
      ))}
    </>
  );

  const Session = ({ a }: { a: TenantChrAccount }) => (
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
          {t('allocation.reconcile.session.down', { defaultValue: 'offline since {{date}}', date: fmt(a.session.lastEndedAt) })}
        </span>
      ) : (
        <span className="text-text-muted">{t('allocation.reconcile.session.never', { defaultValue: 'never seen online' })}</span>
      )}
    </div>
  );

  const AccountCell = ({ a }: { a: TenantChrAccount }) => (
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

  const NearSites = ({ sites }: { sites: TenantNearSite[] }) =>
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

  const policyChr = view?.inventory.find((i) => i.policy) ?? null;

  return (
    <div className="p-6">
      <div className="mb-5 flex flex-wrap items-center justify-between gap-2">
        <h1 className="flex items-center gap-2 text-2xl font-semibold text-text-primary">
          <GitMerge size={22} /> {t('reconcile.title', { defaultValue: 'CHR reconciliation' })}
          <GodViewMarker />
        </h1>
        <div className="flex flex-wrap items-center gap-2">
          {/* God view: one workspace's report at a time — pick it. */}
          <GodViewTenantFilter allowAll={false} onChange={() => void load()} />
          <Button size="sm" variant="secondary" onClick={() => void load()} loading={loading}>
            <RefreshCw size={14} /> {t('allocation.reconcile.refresh', { defaultValue: 'Refresh' })}
          </Button>
          {view && (
            <Button size="sm" variant="secondary" onClick={() => void reread()} loading={rereading} disabled={rereading}>
              <RefreshCw size={14} /> {t('allocation.reconcile.rereadButton', { defaultValue: 'Re-read the CHR' })}
            </Button>
          )}
          {canAttach && (
            <Button size="sm" variant="secondary" onClick={() => setAttachOpen(true)}>
              <Link2 size={14} /> {t('reconcileAttach.button', { defaultValue: 'Attach the online routers' })}
            </Button>
          )}
          {canAccessCheck && (
            <Button
              size="sm"
              variant="secondary"
              onClick={() => setAccessCheckOpen(true)}
              // God view: one workspace at a time — pick it first.
              disabled={godView && godViewTenant === null}
            >
              <ShieldCheck size={14} />{' '}
              {t('accessCheck.button', { defaultValue: 'Verify management access and compliance' })}
            </Button>
          )}
          {view && view.orphans.length > 0 && (
            <a href={reconcileApi.orphansXlsxUrl()}>
              <Button size="sm" variant="secondary">
                <Download size={14} /> {t('allocation.reconcile.orphans.export', { defaultValue: 'Orphans to import (Excel)' })}
              </Button>
            </a>
          )}
        </div>
      </div>

      {godView && godViewTenant === null && (
        <p className="mb-3 rounded-md border border-accent/40 bg-accent/10 px-3 py-2 text-xs text-accent">
          {t('godView.reconcileHint')}
        </p>
      )}

      <p className="mb-4 text-xs text-text-muted">
        {t('reconcile.help', {
          defaultValue:
            "Compares this workspace's sites with the L2TP accounts the concentrator declares for it, as last read. Read-only: nothing is allocated and nothing is written to the concentrator. Accounts of other customers are never shown.",
        })}
      </p>

      {attachOpen && <AttachDevicesDialog onClose={() => setAttachOpen(false)} onAttached={() => void load()} />}
      {accessCheckOpen && (
        <AccessCheckDialog
          onClose={() => {
            setAccessCheckOpen(false);
            setAccessCheckClosed((n) => n + 1);
          }}
        />
      )}
      {canAccessCheck && !(godView && godViewTenant === null) && (
        <AccessCheckNightlyCard
          // Another workspace (or the god view's filter): a fresh card.
          key={`${currentTenantId ?? ''}:${godViewTenant ?? ''}`}
          onOpen={() => setAccessCheckOpen(true)}
          refreshKey={accessCheckClosed}
          canEditSettings={isAdmin()}
        />
      )}

      {refusal && (
        <div className={CARD}>
          <p className="text-sm text-amber-400">{refusalText(refusal)}</p>
        </div>
      )}
      {loading && !view && !refusal && (
        <p className="text-sm text-text-muted">{t('allocation.reconcile.loading', { defaultValue: 'Reading…' })}</p>
      )}

      {view && (
        <>
          <div className={CARD}>
            <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
              <div>
                <div className="text-xs text-text-muted">
                  {t('allocation.reconcile.pattern', { defaultValue: 'Login pattern read' })}
                </div>
                <div className="font-mono text-sm text-text-primary">{view.pattern}</div>
              </div>
              <div>
                <div className="text-xs text-text-muted">
                  {t('allocation.reconcile.inventory', { defaultValue: 'CHR inventory' })}
                </div>
                {view.inventory.map((c, i) => (
                  <div key={i} className="mt-1 text-sm">
                    <span className="text-text-primary">
                      {c.policy
                        ? t('reconcile.policyChr', { defaultValue: 'Concentrator of this workspace' })
                        : t('reconcile.otherChr', { defaultValue: 'Concentrator of earlier allocations' })}
                    </span>
                    <div className={`text-xs ${c.readAt === null ? 'text-red-400' : c.freshness === 'stale' ? 'text-amber-400' : 'text-text-muted'}`}>
                      {c.readAt === null
                        ? t('allocation.reconcile.neverRead', { defaultValue: 'never read: nothing can be reconciled until it is' })
                        : t('reconcile.readAt', { defaultValue: 'last read {{date}}', date: fmt(c.readAt) })}
                    </div>
                    {!c.presenceRecorded && (
                      <div className="text-xs text-amber-400">
                        {t('allocation.reconcile.presence.none', {
                          defaultValue: 'presence has never recorded a session on this CHR: "never seen online" proves nothing here',
                        })}
                      </div>
                    )}
                    {c.degradedSince !== null && (
                      <div className="text-xs text-amber-400">
                        {t('allocation.reconcile.presence.degraded', {
                          defaultValue: 'presence degraded since {{date}}: online states are as they were then',
                          date: fmt(c.degradedSince),
                        })}
                      </div>
                    )}
                    <div className={`text-xs ${c.activeReadAt === null ? 'text-amber-400' : 'text-text-muted'}`}>
                      {c.activeReadAt === null
                        ? t('allocation.reconcile.duplicates.activeNever', {
                            defaultValue: 'live sessions never read: accounts with several sessions cannot be listed',
                          })
                        : t('allocation.reconcile.duplicates.activeReadAt', {
                            defaultValue: 'live sessions read {{date}}',
                            date: fmt(c.activeReadAt),
                          })}
                    </div>
                  </div>
                ))}
                <div className="mt-2 text-xs text-text-muted">
                  {t('allocation.reconcile.generatedAt', { defaultValue: 'Computed {{date}}', date: fmt(view.generatedAt) })}
                </div>
              </div>
            </div>
          </div>

          <div className="mb-3 flex flex-wrap gap-2 text-sm">
            <span className={`${CHIP} text-text-primary`}>
              {t('allocation.reconcile.count.matched', { defaultValue: 'Matched' })}: {view.counts.matched}
            </span>
            <span className={`${CHIP} ${view.counts.orphans > 0 ? 'text-amber-400' : 'text-text-primary'}`}>
              {t('allocation.reconcile.count.orphans', { defaultValue: 'CHR accounts without a site' })}: {view.counts.orphans} ·{' '}
              {t('allocation.reconcile.count.online', { defaultValue: 'online: {{count}}', count: view.counts.orphansOnline })}
            </span>
            <span className={`${CHIP} ${view.counts.siteOnlySuspect > 0 ? 'text-red-400' : 'text-text-primary'}`}>
              {t('allocation.reconcile.count.siteOnly', { defaultValue: 'Sites without a CHR account' })}: {view.counts.siteOnly} ·{' '}
              {t('allocation.reconcile.count.suspect', { defaultValue: 'suspect: {{count}}', count: view.counts.siteOnlySuspect })}
            </span>
            <span className={`${CHIP} ${view.counts.duplicates > 0 ? 'font-semibold text-red-400' : 'text-text-primary'}`}>
              {t('allocation.reconcile.duplicates.count', { defaultValue: 'Accounts with several sessions' })}: {view.counts.duplicates}
            </span>
          </div>
          {policyChr && policyChr.readAt === null && (
            <p className="mb-2 text-sm text-red-400">
              {t('allocation.reconcile.neverReadWarning', {
                defaultValue:
                  "The policy CHR's inventory has never been read: every site below shows as without an account. Re-read the CHR first.",
              })}
            </p>
          )}

          {/* ── Accounts with several live sessions (duplicates) ───────── */}
          <div className={`${CARD} ${view.duplicates.length > 0 ? 'border-red-500/50' : ''}`}>
            <Toggle
              k="duplicates"
              title={t('allocation.reconcile.duplicates.title', { defaultValue: 'Accounts with several sessions (duplicates)' })}
              count={view.duplicates.length}
            />
            {open.duplicates && (
              <>
                <p className="mb-2 text-xs text-text-muted">
                  {t('allocation.reconcile.duplicates.help', {
                    defaultValue:
                      'The concentrator lists several live sessions at once for these accounts: their tunnel address reaches whichever session it routes to, so ObliWAN may be talking to another router (a forgotten one on 4G, say). Attaching them and every job through their tunnel are refused until one session remains: disconnect the extra router, or its session on the concentrator.',
                  })}
                </p>
                {view.duplicates.length === 0 ? (
                  <p className="text-sm text-text-muted">
                    {t('allocation.reconcile.duplicates.none', { defaultValue: 'No account with several sessions in the last read.' })}
                  </p>
                ) : (
                  <div className="overflow-x-auto">
                    <table className="w-full">
                      <thead>
                        <tr>
                          <th className={TH}>{t('allocation.reconcile.col.account', { defaultValue: 'CHR account' })}</th>
                          <th className={TH}>{t('allocation.reconcile.duplicates.col.sessions', { defaultValue: 'Sessions (caller-id, uptime)' })}</th>
                          <th className={TH}>{t('allocation.reconcile.duplicates.col.seen', { defaultValue: 'Seen' })}</th>
                        </tr>
                      </thead>
                      <tbody>
                        {view.duplicates.map((d) => (
                          <tr key={d.account} className="border-t border-border bg-red-500/5">
                            <td className={TD}>
                              <span className="font-mono">{d.account}</span>
                              {d.site && (
                                <div className="text-xs">
                                  <Link to={`/sites/${d.site.siteId}`} className="font-mono hover:underline">
                                    {d.site.code}
                                  </Link>{' '}
                                  <span className="text-text-muted">{d.site.name}</span>
                                </div>
                              )}
                              {!d.site && (
                                <div className="text-xs text-text-muted">
                                  {d.group === 'orphan'
                                    ? t('allocation.reconcile.duplicates.group.orphan', { defaultValue: 'account without a site' })
                                    : t('allocation.reconcile.duplicates.group.offPattern', { defaultValue: 'off-pattern account' })}
                                </div>
                              )}
                              {d.device && (
                                <div className="text-xs text-text-muted">
                                  {t('allocation.reconcile.device', { defaultValue: 'router {{name}}', name: d.device.name })}
                                </div>
                              )}
                            </td>
                            <td className={`${TD} text-xs`}>
                              {d.sessions.map((s, i) => (
                                <div key={i} className="whitespace-nowrap">
                                  <span className="font-mono text-text-primary">
                                    {s.callerId ?? t('allocation.reconcile.duplicates.noCaller', { defaultValue: 'caller-id unknown' })}
                                  </span>
                                  {s.uptime && (
                                    <span className="ml-2 text-text-muted">
                                      {t('allocation.reconcile.duplicates.uptime', { defaultValue: 'up {{uptime}}', uptime: s.uptime })}
                                    </span>
                                  )}
                                  {s.since && (
                                    <span className="ml-2 text-text-muted">
                                      ({t('allocation.reconcile.duplicates.since', { defaultValue: 'since {{date}}', date: fmt(s.since) })})
                                    </span>
                                  )}
                                </div>
                              ))}
                            </td>
                            <td className={`${TD} text-xs text-text-muted`}>
                              <div>
                                {t('allocation.reconcile.duplicates.firstSeen', { defaultValue: 'first seen {{date}}', date: fmt(d.firstSeenAt) })}
                              </div>
                              <div>
                                {t('allocation.reconcile.duplicates.observed', { defaultValue: 'last read {{date}}', date: fmt(d.observedAt) })}
                              </div>
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

          {/* ── Orphans ───────────────────────────────────────────────── */}
          <div className={CARD}>
            <Toggle
              k="orphans"
              title={t('allocation.reconcile.orphans.title', { defaultValue: 'CHR accounts without a site (orphans)' })}
              count={view.orphans.length}
            />
            {open.orphans && (
              <>
                <p className="mb-2 text-xs text-text-muted">
                  {t('reconcile.orphans.help', {
                    defaultValue:
                      "Accounts of this workspace no site claims: a store missing from the sites, or a closed one. Online = a router in production. To create them: “Orphans to import” downloads them in the site import's columns — fill in the names, save as CSV and check it in the Sites page's import: each row then says whether it takes its account over.",
                  })}{' '}
                  <Link to="/sites" className="text-accent hover:underline">
                    {t('reconcile.orphans.openSites', { defaultValue: 'Open the Sites page' })}
                  </Link>
                </p>
                {view.orphans.length === 0 ? (
                  <p className="text-sm text-text-muted">{t('allocation.reconcile.orphans.none', { defaultValue: 'No orphan account.' })}</p>
                ) : (
                  <div className="overflow-x-auto">
                    <table className="w-full">
                      <thead>
                        <tr>
                          <th className={TH}>{t('allocation.reconcile.col.account', { defaultValue: 'CHR account' })}</th>
                          <th className={TH}>{t('allocation.reconcile.col.readBack', { defaultValue: 'Read back' })}</th>
                          <th className={TH}>{t('allocation.reconcile.col.session', { defaultValue: 'Session' })}</th>
                          <th className={TH}>{t('allocation.reconcile.col.near', { defaultValue: 'Resembles' })}</th>
                        </tr>
                      </thead>
                      <tbody>
                        {view.orphans.map((o) => (
                          <tr key={o.account.name} className={`border-t border-border ${o.account.session.up ? 'bg-green-500/5' : ''}`}>
                            <td className={TD}>
                              <AccountCell a={o.account} />
                              {!o.creationAdopts && (
                                <div className="mt-0.5 text-xs font-semibold text-amber-400">
                                  {t('allocation.reconcile.create.wontAdopt', {
                                    defaultValue: 'its allocation would not take this account over',
                                  })}
                                </div>
                              )}
                            </td>
                            <td className={`${TD} font-mono`}>
                              {o.prefill.code ?? o.prefill.name ?? '—'}
                              {o.prefill.country && <span className="ml-1 text-text-muted">({o.prefill.country})</span>}
                            </td>
                            <td className={TD}>
                              <Session a={o.account} />
                            </td>
                            <td className={`${TD} text-xs`}>
                              <NearSites sites={o.nearSites} />
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

          {/* ── Sites without an account ──────────────────────────────── */}
          <div className={CARD}>
            <Toggle
              k="siteOnly"
              title={t('allocation.reconcile.siteOnly.title', { defaultValue: 'Sites without a CHR account' })}
              count={view.siteOnly.length}
            />
            {open.siteOnly && (
              <>
                <p className="mb-2 text-xs text-text-muted">
                  {t('allocation.reconcile.siteOnly.help', {
                    defaultValue:
                      'A new site is normal. A SUSPECT site resembles a live account spelled differently: allocating it would create a second address, then a second CHR account for the same store. Correct the site (code, country) or the template first.',
                  })}
                </p>
                {view.siteOnly.length === 0 ? (
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
                        {view.siteOnly.map((s) => (
                          <tr key={s.siteId} className={`border-t border-border ${s.kind === 'suspect' ? 'bg-amber-500/10' : ''}`}>
                            <td className={TD}>
                              <Link to={`/sites/${s.siteId}`} className="font-mono hover:underline">
                                {s.code}
                              </Link>{' '}
                              <span className="text-text-muted">{s.name}</span>
                              {s.country && <span className="ml-1 text-xs text-text-muted">({s.country})</span>}
                            </td>
                            <td className={`${TD} font-mono`}>
                              {s.login ?? (
                                <span className="font-sans text-red-400" title={s.loginError ?? undefined}>
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
                              {s.allocated && (
                                <div className="text-xs text-text-muted">
                                  {t('reconcile.allocated', { defaultValue: 'already allocated' })}
                                </div>
                              )}
                            </td>
                            <td className={`${TD} text-xs`}>
                              {s.nearMatches.length === 0 && s.withheld === 0 ? (
                                <span className="text-text-muted">—</span>
                              ) : (
                                <>
                                  {s.nearMatches.map((n) => (
                                    <div key={n.account.name} className="text-amber-400">
                                      <span className="font-mono">{n.account.name}</span>
                                      <Reasons reasons={n.reasons} />
                                      <Session a={n.account} />
                                    </div>
                                  ))}
                                  {s.withheld > 0 && (
                                    <div className="text-text-muted">
                                      {t('sites.import.chr.withheld', {
                                        defaultValue: '{{count}} more resembling account(s): a platform administrator must check them',
                                        count: s.withheld,
                                      })}
                                    </div>
                                  )}
                                </>
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

          {/* ── Matched ───────────────────────────────────────────────── */}
          <div className={CARD}>
            <Toggle k="matched" title={t('allocation.reconcile.matched.title', { defaultValue: 'Matched sites' })} count={view.matched.length} />
            {open.matched &&
              (view.matched.length === 0 ? (
                <p className="text-sm text-text-muted">{t('allocation.reconcile.matched.none', { defaultValue: 'No site matched yet.' })}</p>
              ) : (
                <div className="overflow-x-auto">
                  <table className="w-full">
                    <thead>
                      <tr>
                        <th className={TH}>{t('allocation.reconcile.col.site', { defaultValue: 'Site' })}</th>
                        <th className={TH}>{t('allocation.reconcile.col.account', { defaultValue: 'CHR account' })}</th>
                        <th className={TH}>{t('allocation.reconcile.col.session', { defaultValue: 'Session' })}</th>
                        <th className={TH}>{t('allocation.reconcile.col.status', { defaultValue: 'Status' })}</th>
                      </tr>
                    </thead>
                    <tbody>
                      {view.matched.map((m) => (
                        <tr key={m.siteId} className="border-t border-border">
                          <td className={TD}>
                            <Link to={`/sites/${m.siteId}`} className="font-mono hover:underline">
                              {m.code}
                            </Link>{' '}
                            <span className="text-text-muted">{m.name}</span>
                          </td>
                          <td className={TD}>
                            <AccountCell a={m.account} />
                          </td>
                          <td className={TD}>
                            <Session a={m.account} />
                          </td>
                          <td className={TD}>
                            {m.blocked ? (
                              <span className="font-semibold text-amber-400">
                                {t('allocation.reconcile.status.blocked', { defaultValue: 'will not be adopted' })}
                              </span>
                            ) : (
                              t(`allocation.reconcile.status.${m.status}`, {
                                defaultValue: { allocated: 'allocated', adopted: 'adopted', adoptable: 'adoptable' }[m.status],
                              })
                            )}
                            {m.notes.map((n) => (
                              <div key={n} className="text-xs text-text-muted">
                                {n === 'caseDiffers'
                                  ? t('allocation.reconcile.note.caseDiffers', { defaultValue: 'CHR spelling: {{name}}', name: m.account.name })
                                  : t('allocation.reconcile.note.disabled', { defaultValue: 'disabled on the CHR' })}
                              </div>
                            ))}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ))}
          </div>

          {/* ── Off-pattern accounts ──────────────────────────────────── */}
          {view.offPattern.length > 0 && (
            <div className={CARD}>
              <Toggle
                k="offPattern"
                title={t('allocation.reconcile.offPattern.title', { defaultValue: 'Off-pattern accounts' })}
                count={view.offPattern.length}
              />
              {open.offPattern && (
                <div className="overflow-x-auto">
                  <table className="w-full">
                    <thead>
                      <tr>
                        <th className={TH}>{t('allocation.reconcile.col.account', { defaultValue: 'CHR account' })}</th>
                        <th className={TH}>{t('allocation.reconcile.col.why', { defaultValue: 'Why listed' })}</th>
                        <th className={TH}>{t('allocation.reconcile.col.session', { defaultValue: 'Session' })}</th>
                        <th className={TH}>{t('allocation.reconcile.col.near', { defaultValue: 'Resembles' })}</th>
                      </tr>
                    </thead>
                    <tbody>
                      {view.offPattern.map((x) => (
                        <tr key={x.account.name} className="border-t border-border">
                          <td className={TD}>
                            <AccountCell a={x.account} />
                          </td>
                          <td className={`${TD} text-xs text-text-muted`}>
                            {x.via === 'anchor'
                              ? t('allocation.reconcile.via.anchor', { defaultValue: "carries the tenant's fixed part" })
                              : t('allocation.reconcile.via.device', { defaultValue: 'a router of this tenant dials it' })}
                          </td>
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
              )}
            </div>
          )}
        </>
      )}
    </div>
  );
}

export default ReconcilePage;
