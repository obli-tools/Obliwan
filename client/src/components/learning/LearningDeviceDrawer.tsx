import { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { X } from 'lucide-react';
import type { LearnedSiteFacts, LearningCaptureDetail } from '@obliwan/shared';
import { cn } from '@/utils/cn';
import { apiErrorText } from '@/components/variables/valueKinds';
import { RevealSecretButton } from '@/components/secrets/RevealSecretButton';
import { learningApi } from '@/api/learning.api';
import { secretsApi } from '@/api/secrets.api';
import { BreakRiskReport } from './BreakRiskReport';

type Tab = 'facts' | 'secrets' | 'export' | 'breakRisk';

const TH = 'px-2 py-1 text-left text-xs font-medium text-text-muted';
const TD = 'px-2 py-1 text-xs text-text-primary align-top';

/** The redacted copy with its placeholders and withheld lines highlighted. */
function HighlightedExport({ text }: { text: string }) {
  const parts = text.split(/(secret:[a-z0-9][a-z0-9._~-]*|# obliwan: line withheld[^\n]*)/g);
  return (
    <pre className="max-h-[60vh] overflow-auto rounded-md border border-border bg-bg-primary p-2 text-[11px] leading-snug text-text-primary">
      {parts.map((p, i) =>
        p.startsWith('secret:') ? (
          <mark key={i} className="rounded bg-accent/20 px-0.5 text-accent">{p}</mark>
        ) : p.startsWith('# obliwan: line withheld') ? (
          <mark key={i} className="rounded bg-amber-500/20 px-0.5 text-amber-400">{p}</mark>
        ) : (
          <span key={i}>{p}</span>
        ))}
    </pre>
  );
}

function FactsView({ facts }: { facts: LearnedSiteFacts }) {
  const { t } = useTranslation();
  const row = (label: string, value: string | null | undefined, highlight = false) => (
    <tr>
      <td className={TH}>{label}</td>
      <td className={cn(TD, highlight && 'font-semibold text-amber-400')}>{value || '—'}</td>
    </tr>
  );
  return (
    <table className="w-full">
      <tbody>
        {row(t('learning.facts.identity'), facts.identity)}
        {row(t('learning.facts.model'), [facts.model, facts.osVersion].filter(Boolean).join(' · '))}
        {row(t('learning.facts.wan1Port'), facts.wan1.port)}
        {row(t('learning.facts.wan1'), t(`learning.facts.wan1Mode.${facts.wan1.mode}`), facts.wan1.mode === 'static' || facts.wan1.mode === 'ambiguous')}
        {facts.wan1.pppoeName && row(t('learning.facts.pppoe'), facts.wan1.pppoeName)}
        {facts.wan1.staticAddress && row(t('learning.facts.static'), `${facts.wan1.staticAddress} → ${facts.wan1.staticGateway ?? '?'}`, true)}
        {row(t('learning.facts.pppoeClients'), facts.pppoeClients.map((p) => `${p.name}${p.disabled ? ' (off)' : ''}${p.inWanList ? ' ∈ WAN' : ''} @${p.interface ?? '?'}`).join(', '))}
        {row(t('learning.facts.wanList'), facts.wanList.join(', '))}
        {row(t('learning.facts.lan'), facts.lan.status === 'found' ? `${facts.lan.lan} (${facts.lan.routerIp} @${facts.lan.interface})` : t(`learning.facts.lanStatus.${facts.lan.status}`))}
        {row(t('learning.facts.timezone'), facts.timezone)}
        {row(t('learning.facts.apn'), facts.lte.apnProfiles.map((p) => `${p.name}=${p.apn ?? '?'}`).join(', '))}
        {row(t('learning.facts.lte'), [...facts.lte.interfaces, ...facts.lte.selectedProfiles.map((p) => `→ ${p}`)].join(' '))}
        {row(t('learning.facts.defaultRoutes'), facts.defaultRoutes.map((r) => `${r.comment ?? '—'}: ${r.gateway ?? '?'} d=${r.distance ?? '1'}${r.disabled ? ' (off)' : ''}`).join(' | '))}
        {row(t('learning.facts.netwatch'), facts.netwatch.map((n) => `${n.host ?? '?'}${n.comment ? ` (${n.comment})` : ''}${n.disabled ? ' (off)' : ''}`).join(', '))}
        {row(t('learning.facts.l2tp'), facts.l2tpClients.map((l) => `${l.name} → ${l.connectTo ?? '?'}`).join(', '))}
        {row(t('learning.facts.ipsec'), facts.ipsecPeers.map((p) => `${p.name ?? '?'} ${p.address ?? ''}`).join(', '))}
        {row(t('learning.facts.dns'), facts.dnsServers.join(', '))}
        {row(t('learning.facts.ntp'), facts.ntpServers.join(', '))}
        {row(t('learning.facts.scripts'), [...facts.scripts, ...facts.schedulers.map((s) => `⏱ ${s}`)].join(', '))}
        {row(t('learning.facts.counts'), `${facts.counts.lines} · filter ${facts.counts.filter} · nat ${facts.counts.nat} · mangle ${facts.counts.mangle} · address-list ${facts.counts.addressList}`)}
      </tbody>
    </table>
  );
}

/**
 * One router's learning: the latest capture's facts, its vaulted secrets
 * (references only; a value is revealed one at a time behind SECRET_READ),
 * the redacted copy, and the break-risk report.
 */
export function LearningDeviceDrawer({ deviceId, deviceName, onClose }: { deviceId: number; deviceName: string; onClose: () => void }) {
  const { t } = useTranslation();
  const [tab, setTab] = useState<Tab>('facts');
  const [detail, setDetail] = useState<LearningCaptureDetail | null>(null);
  const [loaded, setLoaded] = useState(false);
  const [exportText, setExportText] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    setLoaded(false);
    setDetail(null);
    setExportText(null);
    setError(null);
    learningApi
      .capture(deviceId)
      .then((d) => setDetail(d))
      .catch((err: unknown) => setError(apiErrorText(err) ?? String(err)))
      .finally(() => setLoaded(true));
  }, [deviceId]);

  useEffect(() => {
    if (tab !== 'export' || !detail || exportText !== null || detail.status !== 'succeeded') return;
    learningApi.exportText(detail.captureId).then(setExportText).catch((err: unknown) => setError(apiErrorText(err) ?? String(err)));
  }, [tab, detail, exportText]);

  const tabs: Tab[] = ['facts', 'secrets', 'export', 'breakRisk'];
  return (
    <div className="fixed inset-0 z-40 flex justify-end bg-black/40" onClick={onClose}>
      <div
        className="h-full w-full max-w-3xl overflow-y-auto border-l border-border bg-bg-secondary p-4 shadow-xl"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="mb-3 flex items-center justify-between">
          <h2 className="text-lg font-semibold text-text-primary">{deviceName}</h2>
          <button type="button" className="text-text-muted hover:text-text-primary" onClick={onClose} aria-label={t('common.close')}>
            <X size={18} />
          </button>
        </div>
        <div className="mb-3 flex gap-1 border-b border-border">
          {tabs.map((k) => (
            <button
              key={k}
              type="button"
              onClick={() => setTab(k)}
              className={cn(
                '-mb-px border-b-2 px-3 py-1.5 text-sm',
                tab === k ? 'border-accent text-text-primary' : 'border-transparent text-text-muted hover:text-text-primary',
              )}
            >
              {t(`learning.drawer.${k}`)}
            </button>
          ))}
        </div>

        {error && <div className="mb-3 rounded-md border border-red-500/40 bg-red-500/10 p-2 text-sm text-red-400">{error}</div>}

        {tab !== 'breakRisk' && loaded && !detail && (
          <p className="text-sm text-text-muted">{t('learning.drawer.noCapture')}</p>
        )}
        {tab !== 'breakRisk' && detail && (
          <p className="mb-3 text-xs text-text-muted">
            {t(`learning.status.${detail.status}`)}
            {detail.reason ? ` — ${t(`learning.reason.${detail.reason}`)}` : ''}
            {detail.account ? ` · ${t(`learning.account.${detail.account}`)}` : ''}
            {` · ${new Date(detail.finishedAt ?? detail.startedAt).toLocaleString()}`}
            {detail.detail ? ` · ${detail.detail}` : ''}
          </p>
        )}
        {detail?.snapshotError && tab === 'facts' && (
          <p className="mb-3 text-xs text-amber-400">{t('learning.snapshotError')} {detail.snapshotError}</p>
        )}

        {tab === 'facts' && detail?.facts && <FactsView facts={detail.facts} />}

        {tab === 'secrets' && detail && (
          <div className="space-y-3">
            {detail.secrets.length === 0 ? (
              <p className="text-sm text-text-muted">{t('learning.secrets.none')}</p>
            ) : (
              <table className="w-full">
                <thead>
                  <tr>
                    <th className={TH}>{t('learning.secrets.ref')}</th>
                    <th className={TH}>{t('learning.secrets.shared')}</th>
                    <th className={TH} />
                  </tr>
                </thead>
                <tbody>
                  {detail.secrets.map((s) => (
                    <tr key={s.id} className={cn(s.vanishedAt && 'opacity-50')}>
                      <td className={cn(TD, 'font-mono')}>
                        {s.ref}
                        {s.vanishedAt && <span className="ml-1 text-amber-400">({t('learning.secrets.vanished')})</span>}
                      </td>
                      <td className={TD}>
                        {s.sharedWithSites > 1 ? t('learning.secrets.sharedWith', { count: s.sharedWithSites }) : '—'}
                      </td>
                      <td className={TD}>
                        <RevealSecretButton
                          reveal={() => secretsApi.revealLearnedSecret(s.id)}
                          label={s.prop}
                          resetKey={`${s.id}|${s.fingerprint ?? ''}|${s.lastSeenAt}`}
                        />
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
            {detail.withheld.length > 0 && (
              <div>
                <h3 className="mb-1 text-sm font-semibold text-text-primary">{t('learning.withheld.title')}</h3>
                <p className="mb-1 text-xs text-text-muted">{t('learning.withheld.hint')}</p>
                <ul className="text-xs text-text-primary">
                  {detail.withheld.map((w) => (
                    <li key={w.line} className="font-mono">#{w.line} {w.menu} — {w.props.join(', ')}</li>
                  ))}
                </ul>
              </div>
            )}
          </div>
        )}

        {tab === 'export' && detail && (
          <div>
            <p className="mb-2 text-xs text-text-muted">{t('learning.exportText.hint')}</p>
            {exportText !== null && <HighlightedExport text={exportText} />}
          </div>
        )}

        {tab === 'breakRisk' && <BreakRiskReport deviceId={deviceId} />}
      </div>
    </div>
  );
}
