import { useCallback, useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import toast from 'react-hot-toast';
import { AlertTriangle, ArrowRightLeft, Cable, CheckCircle2, Copy, Loader2 } from 'lucide-react';
import type { ConcentratorLinkView, LinkClientProbe, LinkProbe } from '@obliwan/shared';
import { Button } from '@/components/common/Button';
import { cn } from '@/utils/cn';
import { concentratorLinkApi, linkErrorMessage } from './concentratorLink.api';

/**
 * The ObliWAN <-> concentrator WireGuard link, on the CHR's device page
 * (platform admin only — the route refuses anyone else).
 *
 * Two halves, each with its own state: the CHR side (a change job that only
 * ADDS items on the concentrator) and the host side (the `obliwan-wg` sidecar,
 * which reports through a file). Then, separately and only once the link is
 * PROVEN (fresh handshake, the CHR answering on its transit address), the
 * second gesture: manage the CHR itself through the tunnel, its public address
 * kept as the fallback. Restricting the CHR's own /ip service is shown as a
 * command for the operator — ObliWAN never sends it.
 */

const ACTIVE_STATUSES = new Set(['queued', 'claimed', 'backing_up', 'arming', 'applying', 'verifying', 'soaking', 'disarming']);

function bytes(v: number | null): string {
  if (v === null) return '—';
  if (v < 1024) return `${v} B`;
  if (v < 1024 ** 2) return `${(v / 1024).toFixed(1)} KiB`;
  if (v < 1024 ** 3) return `${(v / 1024 ** 2).toFixed(1)} MiB`;
  return `${(v / 1024 ** 3).toFixed(2)} GiB`;
}

function Row({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div>
      <dt className="text-[11px] uppercase tracking-wider text-text-muted">{label}</dt>
      <dd className="mt-0.5 text-[13px] text-text-primary">{children}</dd>
    </div>
  );
}

function Tone({ ok, warn, children }: { ok?: boolean; warn?: boolean; children: React.ReactNode }) {
  return (
    <span className={cn('inline-flex items-center gap-1', ok ? 'text-status-up' : warn ? 'text-status-warn' : 'text-text-secondary')}>
      {ok ? <CheckCircle2 size={13} /> : warn ? <AlertTriangle size={13} /> : null}
      {children}
    </span>
  );
}

export function ConcentratorLinkCard({ deviceId }: { deviceId: number }) {
  const { t } = useTranslation();
  const [view, setView] = useState<ConcentratorLinkView | null>(null);
  const [loadError, setLoadError] = useState(false);
  const [confirming, setConfirming] = useState(false);
  const [busy, setBusy] = useState(false);
  const [transit, setTransit] = useState('');
  const [port, setPort] = useState('');

  const load = useCallback(async () => {
    try {
      const v = await concentratorLinkApi.get(deviceId);
      setView(v);
      setLoadError(false);
    } catch {
      setLoadError(true);
    }
  }, [deviceId]);

  useEffect(() => {
    void load();
  }, [load]);

  const pending = view?.chrSide === 'pending';
  useEffect(() => {
    const id = setInterval(() => void load(), pending ? 3000 : 30000);
    return () => clearInterval(id);
  }, [load, pending]);

  if (loadError && !view) {
    return (
      <div className="rounded-lg border border-border bg-bg-secondary p-4 text-sm text-text-muted">
        {t('concentratorLink.loadError', { defaultValue: 'The link state could not be read.' })}
      </div>
    );
  }
  if (!view) return null;

  const link = view.link;
  const frozen = link?.frozen ?? false;

  const connect = async () => {
    setBusy(true);
    try {
      const body: { transit?: string | null; listenPort?: number | null } = {};
      if (!frozen && transit.trim() !== '') body.transit = transit.trim();
      if (!frozen && port.trim() !== '') body.listenPort = Number(port.trim());
      const r = await concentratorLinkApi.connect(deviceId, body);
      toast.success(t('concentratorLink.queued', { id: r.jobId, defaultValue: 'Job #{{id}} queued' }));
      setConfirming(false);
      await load();
    } catch (err) {
      toast.error(linkErrorMessage(err, t('concentratorLink.connectError', { defaultValue: 'The connection could not be queued.' })));
    } finally {
      setBusy(false);
    }
  };

  const switchApi = async (via: 'tunnel' | 'public') => {
    setBusy(true);
    try {
      await concentratorLinkApi.switchApi(deviceId, via);
      toast.success(via === 'tunnel'
        ? t('concentratorLink.switchDone', { defaultValue: 'API access now goes through the tunnel.' })
        : t('concentratorLink.revertDone', { defaultValue: 'API access is back on the public address.' }));
      await load();
    } catch (err) {
      toast.error(linkErrorMessage(err, t('concentratorLink.switchError', { defaultValue: 'The API access could not be switched.' })));
      await load();
    } finally {
      setBusy(false);
    }
  };

  const copy = async (text: string) => {
    try {
      await navigator.clipboard.writeText(text);
      toast.success(t('concentratorLink.copied', { defaultValue: 'Copied' }));
    } catch {
      /* clipboard refused: the command stays visible to select by hand */
    }
  };

  const probeText = (p: LinkProbe | null) =>
    p === null
      ? '—'
      : p.reachable
        ? t('concentratorLink.probeOk', { defaultValue: 'answers' })
        : t('concentratorLink.probeKo', { defaultValue: 'no answer' });

  const chrTone = view.chrSide === 'provisioned' ? { ok: true } : view.chrSide === 'failed' ? { warn: true } : {};
  const hostOk = view.host.state === 'up' && view.host.handshakeFresh;
  const job = view.job;
  const jobActive = job !== null && ACTIVE_STATUSES.has(job.status);

  return (
    <div className="rounded-lg border border-border bg-bg-secondary p-4 lg:col-span-2">
      <h3 className="mb-2 flex items-center gap-2 text-sm font-semibold text-text-primary">
        <Cable size={15} /> {t('concentratorLink.title', { defaultValue: 'ObliWAN ↔ site network link' })}
      </h3>
      <p className="mb-3 text-xs text-text-muted">
        {t('concentratorLink.intro', {
          defaultValue:
            "ObliWAN reaches the sites' tunnel addresses (100.64.0.0/10) through a WireGuard link to this concentrator, " +
            'which masquerades that traffic: nothing changes on the sites.',
        })}
      </p>

      <dl className="mb-3 grid grid-cols-2 gap-4">
        <Row label={t('concentratorLink.chrSide', { defaultValue: 'Concentrator side' })}>
          <Tone {...chrTone}>
            {jobActive && <Loader2 size={13} className="animate-spin" />}
            {t(`concentratorLink.chrState.${view.chrSide}`, { defaultValue: view.chrSide })}
          </Tone>
        </Row>
        <Row label={t('concentratorLink.hostSide', { defaultValue: 'ObliWAN host side' })}>
          <Tone ok={hostOk} warn={!hostOk && view.host.state !== 'no_config'}>
            {t(`concentratorLink.hostState.${view.host.state}`, { defaultValue: view.host.state })}
          </Tone>
        </Row>
        <Row label={t('concentratorLink.transit', { defaultValue: 'Transit' })}>
          <span className="font-mono">
            {link ? `${link.transit} (CHR ${link.chrAddress}, ObliWAN ${link.hostAddress})` : view.defaults.transit}
          </span>
        </Row>
        <Row label={t('concentratorLink.listenPort', { defaultValue: 'UDP port' })}>
          <span className="font-mono">{link?.listenPort ?? view.defaults.listenPort}</span>
        </Row>
        <Row label={t('concentratorLink.handshake', { defaultValue: 'Last handshake' })}>
          {view.host.latestHandshakeAt
            ? <Tone ok={view.host.handshakeFresh} warn={!view.host.handshakeFresh}>{new Date(view.host.latestHandshakeAt).toLocaleString()}</Tone>
            : <span className="text-text-muted">{t('concentratorLink.never', { defaultValue: 'never' })}</span>}
        </Row>
        <Row label={t('concentratorLink.traffic', { defaultValue: 'Traffic (rx / tx)' })}>
          <span className="font-mono">{bytes(view.host.rxBytes)} / {bytes(view.host.txBytes)}</span>
        </Row>
        <Row label={t('concentratorLink.probeChr', { defaultValue: 'Concentrator through the link' })}>
          <Tone ok={view.probes.chr?.connected} warn={view.probes.chr !== null && !view.probes.chr.connected}>
            {probeText(view.probes.chr)}
            {view.probes.chr && <span className="font-mono text-text-muted">{` ${view.probes.chr.address}:${view.probes.chr.port}`}</span>}
          </Tone>
        </Row>
      </dl>

      {view.probes.clients.length > 0 && (
        <div className="mb-3">
          <p className="mb-1 text-[11px] uppercase tracking-wider text-text-muted">
            {t('concentratorLink.probeClients', { defaultValue: 'Sites through the link, client by client' })}
          </p>
          <ul className="space-y-1.5">
            {view.probes.clients.map((c: LinkClientProbe) => (
              <li key={c.tenantId ?? 'none'} className="rounded border border-border px-2 py-1.5 text-xs">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <span className="font-medium text-text-primary">
                    {c.tenantName ?? t('concentratorLink.clientUnattributed', { defaultValue: 'Unattributed sessions' })}
                    {c.attribution === 'pool' && (
                      <span className="ml-1 font-normal text-text-muted">
                        {t('concentratorLink.clientByPool', { defaultValue: '(by tunnel pool)' })}
                      </span>
                    )}
                  </span>
                  <Tone ok={c.verdict === 'reached'} warn={c.verdict !== 'reached'}>
                    {t(`concentratorLink.clientVerdict.${c.verdict}`, {
                      answered: c.sites.filter((x) => x.reachable).length,
                      probed: c.sites.length,
                      defaultValue: c.verdict === 'reached'
                        ? 'reached'
                        : c.verdict === 'partial' ? '{{answered}}/{{probed}} answer' : 'no site answers',
                    })}
                  </Tone>
                </div>
                <p className="text-text-muted">
                  {t('concentratorLink.clientSessions', {
                    live: c.liveSessions,
                    stable: c.stableSessions,
                    defaultValue: '{{live}} live sessions, {{stable}} stable',
                  })}
                </p>
                <ul className="mt-0.5 space-y-0.5">
                  {c.sites.map((site) => (
                    <li key={site.address} className="flex flex-wrap items-center gap-x-2">
                      <Tone ok={site.reachable} warn={!site.reachable}>{probeText(site)}</Tone>
                      <span className="font-mono text-text-muted">{`${site.name ?? ''} ${site.address}`.trim()}</span>
                      {!site.stable && (
                        <span className="text-status-warn">
                          {t('concentratorLink.siteYoung', { defaultValue: 'recently connected — weak evidence' })}
                        </span>
                      )}
                    </li>
                  ))}
                </ul>
              </li>
            ))}
          </ul>
          {view.probes.clientsNotProbed > 0 && (
            <p className="mt-1 text-xs text-text-muted">
              {t('concentratorLink.clientsNotProbed', {
                count: view.probes.clientsNotProbed,
                defaultValue: '{{count}} more clients not tested',
              })}
            </p>
          )}
        </div>
      )}

      {view.host.message && view.host.state !== 'up' && (
        <p className="mb-2 text-xs text-text-secondary">{view.host.message}</p>
      )}
      {view.probes.skipped && (
        <p className="mb-2 text-xs text-text-muted">
          {t('concentratorLink.probeSkipped', { reason: view.probes.skipped, defaultValue: 'Not tested: {{reason}}' })}
        </p>
      )}
      {view.host.warnings.length > 0 && (
        <ul className="mb-2 list-disc pl-5 text-xs text-status-warn">
          {view.host.warnings.map((w) => <li key={w}>{w}</li>)}
        </ul>
      )}

      {job && (
        <div className="mb-3 rounded border border-border p-2">
          <p className="mb-1 text-xs font-semibold text-text-secondary">
            {t('concentratorLink.progress', { id: job.id, defaultValue: 'Job #{{id}}' })} — {job.status}
          </p>
          <ol className="space-y-0.5 text-xs">
            {job.steps.map((s, i) => (
              <li key={`${s.kind}-${i}`} className={cn(s.status === 'failed' ? 'text-status-down' : 'text-text-secondary')}>
                <span className="font-mono">{t(`change.step.${s.kind}`, { defaultValue: s.kind })}</span>
                {` — ${s.status}`}
                {s.output && <span className="block pl-3 text-text-muted">{s.output}</span>}
              </li>
            ))}
          </ol>
          {job.errorMessage && <p className="mt-1 text-xs text-status-down">{job.errorMessage}</p>}
        </div>
      )}

      {view.hostBoundTo && (
        <p className="mb-3 rounded border border-status-warn/40 bg-status-warn/5 p-2 text-xs text-text-secondary">
          {t('concentratorLink.hostBoundTo', {
            name: view.hostBoundTo.name,
            defaultValue:
              'The ObliWAN host already follows {{name}}: it carries one WireGuard link for all of 100.64.0.0/10, ' +
              'so this concentrator cannot be connected as well. ObliWAN has no operation that unbinds a link.',
          })}
        </p>
      )}

      {!jobActive && !confirming && !view.hostBoundTo && (
        <div className="mb-3 flex flex-wrap items-end gap-2">
          {!frozen && (
            <>
              <label className="text-xs text-text-muted">
                {t('concentratorLink.transit', { defaultValue: 'Transit' })}
                <input
                  className="mt-0.5 block w-44 rounded border border-border bg-bg-primary px-2 py-1 font-mono text-xs text-text-primary"
                  placeholder={link?.transit ?? view.defaults.transit}
                  value={transit}
                  onChange={(e) => setTransit(e.target.value)}
                />
              </label>
              <label className="text-xs text-text-muted">
                {t('concentratorLink.listenPort', { defaultValue: 'UDP port' })}
                <input
                  className="mt-0.5 block w-24 rounded border border-border bg-bg-primary px-2 py-1 font-mono text-xs text-text-primary"
                  placeholder={String(link?.listenPort ?? view.defaults.listenPort)}
                  value={port}
                  onChange={(e) => setPort(e.target.value.replace(/[^0-9]/g, ''))}
                />
              </label>
            </>
          )}
          <Button size="sm" onClick={() => setConfirming(true)} disabled={busy}>
            <Cable size={14} className="mr-1.5" />
            {view.chrSide === 'provisioned'
              ? t('concentratorLink.reconnect', { defaultValue: 'Run the connection again (changes nothing if all is in place)' })
              : t('concentratorLink.connect', { defaultValue: 'Connect ObliWAN to the site network' })}
          </Button>
        </div>
      )}

      {confirming && (
        <div className="mb-3 rounded border border-status-warn/40 bg-status-warn/5 p-3">
          <p className="mb-1 text-xs font-semibold text-text-primary">
            {t('concentratorLink.confirmTitle', { defaultValue: 'Before you confirm' })}
          </p>
          <p className="mb-2 text-xs text-text-secondary">
            {t('concentratorLink.confirmBody', {
              defaultValue:
                'This job only ADDS items on the concentrator: a WireGuard interface, an address, a peer, accept rules and ' +
                "one masquerade rule limited to ObliWAN's transit address. It never modifies or removes anything, and arms " +
                'no dead-man: nothing it adds can cut the path ObliWAN uses to manage the concentrator (its public ' +
                'address). Before its first write it must take a backup of the concentrator; if that backup cannot be ' +
                'taken, the job stops at that step and writes nothing. The step says why.',
            })}
          </p>
          <div className="flex gap-2">
            <Button size="sm" onClick={() => void connect()} disabled={busy}>
              {busy && <Loader2 size={13} className="mr-1.5 animate-spin" />}
              {t('concentratorLink.confirm', { defaultValue: 'Confirm and connect' })}
            </Button>
            <Button size="sm" variant="ghost" onClick={() => setConfirming(false)} disabled={busy}>
              {t('concentratorLink.cancel', { defaultValue: 'Cancel' })}
            </Button>
          </div>
        </div>
      )}

      {/* ── The second, separate gesture ── */}
      <div className="border-t border-border pt-3">
        <p className="mb-1 text-xs font-semibold text-text-secondary">
          {t('concentratorLink.switchTitle', { defaultValue: "Concentrator API through the tunnel" })}
        </p>
        {!view.apiTransport.viaTunnel ? (
          <>
            <p className="mb-2 text-xs text-text-muted">
              {t('concentratorLink.switchExplain', {
                address: link?.chrAddress ?? '—',
                defaultValue:
                  'Separate step, once the link is proven: ObliWAN then manages this concentrator through {{address}} ' +
                  'instead of its public address, which is kept as the fallback.',
              })}
            </p>
            {!view.canSwitchApi && view.switchBlockers.length > 0 && (
              <p className="mb-2 text-xs text-text-muted">
                {t('concentratorLink.switchBlocked', { defaultValue: 'Not available yet:' })} {view.switchBlockers.join('; ')}
              </p>
            )}
            <Button size="sm" variant="secondary" onClick={() => void switchApi('tunnel')} disabled={busy || !view.canSwitchApi}>
              <ArrowRightLeft size={14} className="mr-1.5" />
              {t('concentratorLink.switchButton', { defaultValue: "Move the concentrator's API access into the tunnel" })}
            </Button>
          </>
        ) : (
          <>
            <p className="mb-1 text-xs text-text-secondary">
              {t('concentratorLink.switched', {
                address: view.apiTransport.host ?? '',
                at: link?.apiViaTunnelAt ? new Date(link.apiViaTunnelAt).toLocaleString() : '',
                defaultValue: 'ObliWAN manages this concentrator through {{address}} since {{at}}.',
              })}
            </p>
            <p className="mb-2 text-xs text-text-muted">
              {t('concentratorLink.fallback', {
                host: link?.apiPublicHost ?? '',
                port: link?.apiPublicPort ?? '',
                defaultValue: 'Fallback: {{host}}:{{port}} (the public address), restored by the button below.',
              })}
            </p>
            <Button size="sm" variant="ghost" onClick={() => void switchApi('public')} disabled={busy}>
              <ArrowRightLeft size={14} className="mr-1.5" />
              {t('concentratorLink.revert', { defaultValue: 'Go back to the public address' })}
            </Button>

            {view.operatorCommand && (
              <div className="mt-3 rounded border border-border p-2">
                <p className="mb-1 text-xs font-semibold text-text-secondary">
                  {t('concentratorLink.operatorTitle', {
                    defaultValue: 'To do by hand on the concentrator (ObliWAN never does it)',
                  })}
                </p>
                <div className="mb-1 flex items-center gap-2">
                  <code className="min-w-0 break-all rounded bg-bg-primary px-2 py-1 font-mono text-xs text-text-primary">{view.operatorCommand}</code>
                  <Button size="sm" variant="ghost" onClick={() => void copy(view.operatorCommand ?? '')}>
                    <Copy size={13} />
                  </Button>
                </div>
                <p className="text-xs text-status-warn">
                  {t('concentratorLink.operatorWarn', {
                    defaultValue:
                      'This restricts the API service to ObliWAN through the tunnel. Do not touch the winbox and ssh ' +
                      'services: keep your own access, and test from a second session before closing yours. If you use ' +
                      'the API yourself from elsewhere, add your address to the list. It also closes the public fallback ' +
                      'above until you widen it again.',
                  })}
                </p>
              </div>
            )}
          </>
        )}
      </div>
    </div>
  );
}
