import { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Antenna, ArrowLeftRight, BellRing, ShieldAlert, Smartphone } from 'lucide-react';
import apiClient from '@/api/client';
import type { ApiResponse, SiteUplinkKind } from '@obliwan/shared';
import { cn } from '@/utils/cn';
import { Backup4gSims, shortDate, type Backup4gSim } from '@/components/telemetry/Backup4gBits';

/**
 * Which WAN this site is actually on.
 *
 * Two answers, never merged: what the routing SAYS should carry traffic, and
 * what the counters show IS carrying it. The failover signal is `onBackup`
 * (the busiest carrying link is cellular), drawn as the warning — NOT the two
 * answers disagreeing. Against the configuration (intent), traffic on the SIM
 * while the intent names the primary is the failover the configuration does
 * not say. Against the router's live route (a fact), the table names the SIM
 * after a failover, so the two AGREE on the cellular link and that agreement
 * is the failover. Agreement on a primary-class link is the only "nothing to
 * read".
 *
 * "Routing says" names where it comes from: the configuration (intent), or the
 * router's active default route as the health check last read it (a fact with
 * an age, flagged stale past 24 h — never shown as current). When neither
 * answers it says WHY (`liveRouteStatus`): "not read yet" only when the health
 * check will read it, otherwise the reason nothing will. Tunnels (l2tp-mgmt,
 * l2tp-infra, …) are listed apart: their bytes already cross the uplink, so
 * they are never one.
 *
 * THE SITE'S DECLARATION (migration 076) changes how it is DRAWN, never what
 * is measured: on a site declared 4G-only, traffic on the cellular link is
 * the nominal path — no warning colour, no failover wording, a "site
 * declared 4G only" badge — while `onBackup` still says the bytes are on a
 * metered link.
 */

interface Candidate {
  ifName: string; alias: string | null; kind: string; operStatus: number;
  inBps: number | null; outBps: number | null; samples: number; carrying: boolean | null;
}
type TunnelRole = 'management' | 'infrastructure' | 'tunnel';
interface Tunnel {
  ifName: string; alias: string | null; role: TunnelRole; operStatus: number;
  inBps: number | null; outBps: number | null; samples: number;
}
interface LiveRoute { iface: string | null; gateway: string | null; observedAt: string; stale: boolean }
/** Why there is no live reading (server `LiveRouteStatus`). */
type LiveRouteStatus =
  | 'read' | 'not_yet' | 'no_api_channel' | 'not_routeros' | 'concentrator' | 'no_identity' | 'not_polled';
interface Asn { asn: number; name: string | null; prefix: string | null; countryCode: string | null }
/** The 4G backup watch (server `Backup4gDeviceView`, migration 075). */
interface Backup4g {
  iface: string | null; cellular: boolean; since: string | null; observedAt: string | null;
  alertedAt: string | null; delayMin: number; held: boolean; fixedUplinks: string[];
  /** The site's declared access link; absent on an older server = not declared. */
  declaredUplink?: SiteUplinkKind | null;
  /** null = the session does not hold SIM_READ, not "no line". */
  sims: Backup4gSim[] | null;
  transitions: Array<{ from: string | null; to: string | null; at: string }>;
}
interface Verdict {
  configured: string | null; observed: string | null; onBackup: boolean | null;
  configuredSource?: 'snapshot' | 'live' | null; configuredAt?: string | null;
  configuredStale?: boolean; liveRoute?: LiveRoute | null; liveRouteStatus?: LiveRouteStatus;
  reason: string; candidates: Candidate[]; tunnels?: Tunnel[]; windowMinutes: number;
  publicIp: string | null; asn: Asn | null; asnLookupEnabled: boolean;
  /** The site's declared access link (server `declaredUplink`). */
  declaredUplink?: SiteUplinkKind | null;
  backup4g?: Backup4g | null;
}

/** What `GET /devices/:id/uplink` answers — read by the device page's status
 *  chip and its « 4G / SIM » tab through `onView`, never fetched twice. */
export type UplinkVerdict = Verdict;
export type Backup4gWatch = Backup4g;

/** True when the site is declared 4G-only: the cellular link is its nominal
 *  path, so traffic on it is never drawn as a failover. */
export function isCellularOnly(v: UplinkVerdict): boolean {
  return (v.declaredUplink ?? v.backup4g?.declaredUplink ?? null) === 'cellular_only';
}

function bps(v: number | null): string {
  if (v === null) return '—';
  if (v < 1000) return `${v} b/s`;
  if (v < 1e6) return `${(v / 1000).toFixed(1)} kb/s`;
  if (v < 1e9) return `${(v / 1e6).toFixed(1)} Mb/s`;
  return `${(v / 1e9).toFixed(2)} Gb/s`;
}

/** "3 minutes ago" / "il y a 3 minutes", from Intl so no string needs translating. */
function relative(iso: string | null | undefined, lang: string): string | null {
  if (!iso) return null;
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return null;
  const diffS = Math.round((d.getTime() - Date.now()) / 1000);
  const a = Math.abs(diffS);
  const rtf = new Intl.RelativeTimeFormat(lang, { numeric: 'auto' });
  return a < 60 ? rtf.format(diffS, 'second')
    : a < 3600 ? rtf.format(Math.round(diffS / 60), 'minute')
      : a < 86_400 ? rtf.format(Math.round(diffS / 3600), 'hour')
        : rtf.format(Math.round(diffS / 86_400), 'day');
}

function StaleBadge() {
  const { t } = useTranslation();
  return (
    <span className="ml-1.5 rounded-full border border-status-warn/40 bg-status-warn/10 px-1.5 font-sans text-[10px] text-status-warn">
      {t('uplink.stale')}
    </span>
  );
}

/** Where "routing says" comes from, and how old it is — or why it is empty. */
function RoutingSource({ v, lang }: { v: Verdict; lang: string }) {
  const { t } = useTranslation();
  const live = v.liveRoute ?? null;
  const liveAge = relative(live?.observedAt, lang);
  const line = 'mt-0.5 font-sans text-[11px] text-text-muted';

  if (v.configured && v.configuredSource === 'snapshot') {
    const age = relative(v.configuredAt, lang);
    return (
      <>
        <p className={line}>
          {age ? t('uplink.sourceSnapshot', { age }) : t('uplink.sourceSnapshotUndated')}
        </p>
        {/* The live table naming something else is the failover seen from the
            routing side: shown, not hidden behind the intent. */}
        {live && liveAge && live.iface !== v.configured && (
          <p className={cn(line, 'text-text-secondary')}>
            {live.iface
              ? t('uplink.liveDiffers', { iface: live.iface, age: liveAge })
              : live.gateway
                ? t('uplink.gatewayOnly', { gateway: live.gateway, age: liveAge })
                : t('uplink.noActiveRoute', { age: liveAge })}
            {live.stale && <StaleBadge />}
          </p>
        )}
      </>
    );
  }
  if (v.configured && v.configuredSource === 'live') {
    const age = relative(v.configuredAt, lang);
    return (
      <p className={line}>
        {age ? t('uplink.sourceLive', { age }) : t('uplink.sourceLiveUndated')}
        {v.configuredStale && <StaleBadge />}
      </p>
    );
  }
  // Nothing names an interface: say which of the two reasons it is.
  if (live && liveAge) {
    return (
      <p className={line}>
        {live.gateway
          ? t('uplink.gatewayOnly', { gateway: live.gateway, age: liveAge })
          : t('uplink.noActiveRoute', { age: liveAge })}
        {live.stale && <StaleBadge />}
      </p>
    );
  }
  // "Not read yet" only when the health check will read it; otherwise say
  // why nothing will, and what would change that.
  const unread: Partial<Record<LiveRouteStatus, string>> = {
    no_api_channel: 'uplink.unread.noApiChannel',
    not_routeros: 'uplink.unread.notRouterOs',
    concentrator: 'uplink.unread.concentrator',
    no_identity: 'uplink.unread.noIdentity',
    not_polled: 'uplink.unread.notPolled',
  };
  const key = v.liveRouteStatus ? unread[v.liveRouteStatus] : undefined;
  return <p className={line}>{t(key ?? 'uplink.neverRead')}</p>;
}

/** Where the 4G backup watch stands for this router. Draws nothing when the
 *  router never was on its cellular link and nothing was alerted. */
export function Backup4gSection({ b, lang, className }: { b: Backup4g; lang: string; className?: string }) {
  const { t } = useTranslation();
  if (!b.cellular && !b.alertedAt && b.transitions.length === 0) return null;
  const line = 'text-[11px] text-text-muted';
  const cellularOnly = b.declaredUplink === 'cellular_only';
  return (
    <div className={className ?? 'mt-3 border-t border-border pt-2'}>
      <p className="mb-1 flex items-center gap-1.5 text-[11px] uppercase tracking-wider text-text-muted">
        <Smartphone size={12} /> {cellularOnly ? t('uplink.backup4g.titleCellularOnly') : t('uplink.backup4g.title')}
      </p>
      {b.iface && (
        <p className={cn('text-xs', b.cellular && !cellularOnly ? 'text-status-warn' : 'text-text-secondary')}>
          {b.cellular
            ? b.since
              ? t('uplink.backup4g.onCellularSince', {
                iface: b.iface, date: shortDate(b.since, lang), ago: relative(b.since, lang) ?? '',
              })
              : t('uplink.backup4g.onCellularNoSince', { iface: b.iface })
            : t('uplink.backup4g.onFixed', { iface: b.iface })}
        </p>
      )}
      {b.alertedAt && (
        <p className="mt-0.5 flex items-center gap-1 text-[11px] text-status-warn">
          <BellRing size={11} /> {t('uplink.backup4g.alerted', { ago: relative(b.alertedAt, lang) ?? '' })}
        </p>
      )}
      {b.cellular && !b.alertedAt && (
        <p className={line}>
          {cellularOnly
            ? t('uplink.backup4g.declaredCellularOnly')
            : b.delayMin <= 0
              ? t('uplink.backup4g.off')
              : b.fixedUplinks.length === 0 && b.declaredUplink !== 'fixed'
                ? t('uplink.backup4g.noFixed')
                : b.held
                  ? t('uplink.backup4g.held')
                  : t('uplink.backup4g.due', { minutes: b.delayMin })}
        </p>
      )}
      {b.declaredUplink === 'fixed' && b.fixedUplinks.length === 0 && (
        <p className={line}>{t('uplink.backup4g.declaredFixed')}</p>
      )}
      {b.fixedUplinks.length > 0 && (
        <p className={line}>{t('uplink.backup4g.fixed', { names: b.fixedUplinks.join(', ') })}</p>
      )}
      {b.sims !== null && (b.cellular || b.alertedAt) && (
        <div className="mt-1.5">
          <p className={line}>{t('uplink.backup4g.simTitle')}</p>
          <Backup4gSims sims={b.sims} lang={lang} />
        </div>
      )}
      {b.transitions.length > 0 && (
        <div className="mt-1.5">
          <p className={line}>{t('uplink.backup4g.transitions')}</p>
          <ul className="space-y-0.5">
            {b.transitions.map((tr) => (
              <li key={tr.at} className="flex flex-wrap gap-x-2 text-[11px]">
                <span className="font-mono text-text-secondary">
                  {tr.from ?? t('uplink.backup4g.unknownIface')} → {tr.to ?? t('uplink.backup4g.unknownIface')}
                </span>
                <span className="text-text-muted">{shortDate(tr.at, lang)}</span>
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}

export function DeviceUplinkCard({
  deviceId,
  embedded = false,
  onView,
}: {
  deviceId: number;
  /** Drawn inside a device-page section that already carries the frame and
   *  the title: the card then draws neither. */
  embedded?: boolean;
  /** The verdict once read (`null`: it could not be). The device page builds
   *  its uplink chip and its 4G backup block from it. */
  onView?: (view: UplinkVerdict | null) => void;
}) {
  const { t, i18n } = useTranslation();
  const [v, setV] = useState<Verdict | null>(null);
  const [failed, setFailed] = useState(false);

  useEffect(() => {
    let alive = true;
    apiClient
      .get<ApiResponse<Verdict>>(`/devices/${deviceId}/uplink`)
      .then((r) => { if (alive) { setV(r.data.data ?? null); setFailed(!r.data.data); } })
      .catch(() => { if (alive) { setV(null); setFailed(true); } });
    return () => { alive = false; };
  }, [deviceId]);

  useEffect(() => {
    if (v) onView?.(v);
    else if (failed) onView?.(null);
  }, [v, failed, onView]);

  if (!v) return null;
  const lang = i18n.language;
  const tunnels = v.tunnels ?? [];
  // Declared 4G-only: the cellular link is the nominal path, never drawn as a warning.
  const cellularOnly = isCellularOnly(v);
  const warn = !!v.onBackup && !cellularOnly;
  // Measured, and nothing above the noise floor: an answer, not an absence.
  const allIdle = v.observed === null
    && v.candidates.some((c) => c.carrying === false)
    && !v.candidates.some((c) => c.carrying === true);

  return (
    <div className={embedded ? undefined : 'rounded-lg border border-border bg-bg-secondary p-4'}>
      {(!embedded || cellularOnly) && (
        <h3 className="mb-2 flex flex-wrap items-center gap-2 text-sm font-semibold text-text-primary">
          {!embedded && <><Antenna size={15} /> {t('uplink.title')}</>}
          {cellularOnly && (
            <span className="rounded-full border border-accent/40 bg-accent/10 px-1.5 py-0.5 text-[10px] font-medium text-accent">
              {t('uplink.declaredCellularOnly')}
            </span>
          )}
        </h3>
      )}

      <div className="mb-3 flex items-start gap-2">
        {warn
          ? <ShieldAlert size={16} className="mt-0.5 shrink-0 text-status-warn" />
          : <ArrowLeftRight size={16} className="mt-0.5 shrink-0 text-text-muted" />}
        <p className={cn('text-sm', warn ? 'text-status-warn' : 'text-text-secondary')}>
          {v.reason}
        </p>
      </div>

      <dl className="mb-3 grid grid-cols-2 gap-4">
        <div>
          <dt className="text-[11px] uppercase tracking-wider text-text-muted">
            {t('uplink.configured')}
          </dt>
          <dd className="mt-0.5 font-mono text-[13px] text-text-primary">
            {v.configured ?? <span className="text-text-muted">—</span>}
            <RoutingSource v={v} lang={lang} />
          </dd>
        </div>
        <div>
          <dt className="text-[11px] uppercase tracking-wider text-text-muted">
            {t('uplink.observed')}
          </dt>
          <dd className="mt-0.5 font-mono text-[13px] text-text-primary">
            {v.observed ?? <span className="text-text-muted">—</span>}
            {allIdle && (
              <p className="mt-0.5 font-sans text-[11px] text-text-muted">{t('uplink.idle')}</p>
            )}
          </dd>
        </div>
        {/* The outside view: the address the CONCENTRATOR saw this site dial in
            from, and who announces it. Independent of anything the router says
            about itself, which is why it is worth its own line. */}
        {v.publicIp && (
          <div className="col-span-2">
            <dt className="text-[11px] uppercase tracking-wider text-text-muted">
              {t('uplink.egress')}
            </dt>
            <dd className="mt-0.5 font-mono text-[13px] text-text-primary">
              {v.publicIp}
              {v.asn && (
                <span className="ml-2 text-text-secondary">
                  AS{v.asn.asn}{v.asn.name ? ` · ${v.asn.name}` : ''}
                </span>
              )}
              {!v.asn && !v.asnLookupEnabled && (
                <span className="ml-2 font-sans text-[11px] text-text-muted">
                  {t('uplink.asnDisabled')}
                </span>
              )}
            </dd>
          </div>
        )}
      </dl>

      <ul className="space-y-1">
        {v.candidates.map((c) => (
          <li key={c.ifName} className="flex flex-wrap items-baseline gap-2 text-xs">
            <span className={cn(
              'font-mono',
              c.carrying ? 'text-text-primary' : 'text-text-muted',
            )}>
              {c.ifName}
            </span>
            <span className="rounded-full border border-border px-1.5 text-[10px] text-text-muted">
              {c.kind}
            </span>
            {c.alias && <span className="text-[11px] text-text-muted">{c.alias}</span>}
            {/* `null` is not zero: a rate needs two samples, and saying "0 b/s"
                about a link nobody has measured twice is a false negative. */}
            <span className="ml-auto font-mono text-[11px] text-text-secondary">
              {c.samples < 2
                ? t('uplink.awaitingSecondSample')
                : `↓ ${bps(c.inBps)} · ↑ ${bps(c.outBps)}`}
            </span>
          </li>
        ))}
      </ul>

      {tunnels.length > 0 && (
        <div className="mt-3 border-t border-border pt-2">
          <p className="text-[11px] uppercase tracking-wider text-text-muted">{t('uplink.tunnels')}</p>
          <p className="mb-1 text-[11px] text-text-muted">{t('uplink.tunnelsNote')}</p>
          <ul className="space-y-1">
            {tunnels.map((tn) => (
              <li key={tn.ifName} className="flex flex-wrap items-baseline gap-2 text-xs">
                <span className={cn('font-mono', tn.operStatus === 1 ? 'text-text-primary' : 'text-text-muted')}>
                  {tn.ifName}
                </span>
                <span className="rounded-full border border-border px-1.5 text-[10px] text-text-muted">
                  {t(`uplink.role.${tn.role}`)}
                </span>
                {tn.alias && <span className="text-[11px] text-text-muted">{tn.alias}</span>}
                <span className="ml-auto font-mono text-[11px] text-text-secondary">
                  {tn.samples < 2
                    ? t('uplink.awaitingSecondSample')
                    : `↓ ${bps(tn.inBps)} · ↑ ${bps(tn.outBps)}`}
                </span>
              </li>
            ))}
          </ul>
        </div>
      )}

      {v.backup4g && <Backup4gSection b={v.backup4g} lang={lang} />}

      <p className="mt-2 text-[11px] text-text-muted">
        {t('uplink.window', { minutes: v.windowMinutes })}
      </p>
    </div>
  );
}
