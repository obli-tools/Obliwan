import type { ReactNode } from 'react';
import { Link } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import {
  Activity, Antenna, GitCompareArrows, KeyRound, ListChecks, MapPin, Network,
  Radio, Router, ShieldAlert, Smartphone, Users,
} from 'lucide-react';
import { PresenceDot } from '@/components/fleet/PresenceDot';
import { TenantBadge } from '@/components/common/TenantBadge';
import { cn } from '@/utils/cn';
import { anonHostname } from '@/utils/anonymize';
import { deviceStatusStyle } from '@/utils/verdict';
import type { DeviceDetail, DevicePresence } from '@/types/fleet';
import {
  complianceSignal, deadmanSignal, driftSignal, healthSignal, managementSignal,
  presenceSignal, simSignal, uplinkSignal, type Signal,
} from './deviceSignals';
import type { DeviceSignalSources } from './useDeviceSignals';
import type { PageTarget } from './devicePage';
import { TONE_PILL, ToneDot } from './StatusSection';
import { SiteOpenStateInline } from '@/components/sites/OpeningHours';

/**
 * The top of a device page: who the box is, where it belongs, a row of chips
 * that answers « is it OK? » in one glance, and the actions.
 *
 * Every chip is a button to the section (or tab) that explains it — a chip
 * that only colours a word sends the operator hunting for the reason.
 */

interface Chip {
  key: string;
  topic: string;
  icon: ReactNode;
  signal: Signal;
  target: PageTarget;
}

function DeviceStatusChips({
  device,
  presence,
  sources,
  onSelect,
}: {
  device: DeviceDetail;
  presence: DevicePresence | null;
  sources: DeviceSignalSources;
  onSelect: (target: PageTarget) => void;
}) {
  const { t } = useTranslation();
  const isMikrotikCpe = device.brand === 'mikrotik' && device.role !== 'concentrator';

  const candidates: Array<Omit<Chip, 'signal'> & { signal: Signal | null }> = [
    {
      key: 'presence', topic: t('devices.page.chips.presence'), icon: <Network size={12} />,
      signal: presenceSignal(t, presence?.verdict), target: { tab: 'overview', section: 'reachability' },
    },
    {
      key: 'health', topic: t('devices.page.chips.health'), icon: <Activity size={12} />,
      signal: healthSignal(t, device.healthCheck), target: { tab: 'overview', section: 'reachability' },
    },
    {
      key: 'management', topic: t('devices.page.chips.management'), icon: <KeyRound size={12} />,
      signal: isMikrotikCpe ? managementSignal(t, sources.management) : null,
      target: { tab: 'overview', section: 'management' },
    },
    {
      key: 'compliance', topic: t('devices.page.chips.compliance'), icon: <ListChecks size={12} />,
      signal: isMikrotikCpe ? complianceSignal(t, sources.compliance) : null,
      target: { tab: 'overview', section: 'compliance' },
    },
    {
      key: 'uplink', topic: t('devices.page.chips.uplink'), icon: <Antenna size={12} />,
      signal: uplinkSignal(t, sources.uplink), target: { tab: 'overview', section: 'uplink' },
    },
    {
      key: 'sim', topic: t('devices.page.chips.sim'), icon: <Smartphone size={12} />,
      signal: simSignal(t, sources.sim), target: { tab: 'sim' },
    },
    {
      key: 'drift', topic: t('devices.page.chips.drift'), icon: <GitCompareArrows size={12} />,
      signal: driftSignal(t, sources.drift), target: { tab: 'drift' },
    },
  ];
  // A router that cannot carry a dead-man is worth a chip; one that can, or
  // was never asked, is said in the identity card — not as noise up here.
  if (device.brand === 'mikrotik') {
    const deadman = deadmanSignal(t, device.deviceMode);
    if (deadman.tone === 'bad') {
      candidates.push({
        key: 'deadman', topic: t('devices.page.chips.deadman'), icon: <ShieldAlert size={12} />,
        signal: deadman, target: { tab: 'overview', section: 'identity' },
      });
    }
  }
  const chips = candidates.filter((c): c is Chip => c.signal !== null);

  return (
    <ul aria-label={t('devices.page.chipsLabel')} className="flex flex-wrap gap-1.5">
      {chips.map((c) => (
        <li key={c.key}>
          <button
            type="button"
            onClick={() => onSelect(c.target)}
            title={t('devices.page.chipHint')}
            className={cn(
              'inline-flex max-w-full items-center gap-1.5 rounded-full border px-2.5 py-1 text-xs transition-opacity hover:opacity-80',
              TONE_PILL[c.signal.tone],
            )}
          >
            <ToneDot tone={c.signal.tone} />
            <span className="inline-flex items-center gap-1 opacity-75">{c.icon}{c.topic}</span>
            <span className="truncate font-medium">{c.signal.value}</span>
          </button>
        </li>
      ))}
    </ul>
  );
}

export function DeviceHeader({
  device,
  presence,
  siteName,
  readOnly,
  sources,
  onSelect,
  actions,
}: {
  device: DeviceDetail;
  presence: DevicePresence | null;
  siteName: string | null;
  /** The session may see this device but not change it. */
  readOnly: boolean;
  sources: DeviceSignalSources;
  onSelect: (target: PageTarget) => void;
  /** The page's action buttons: it owns their handlers and their gates. */
  actions: ReactNode;
}) {
  const { t } = useTranslation();

  // What the box is, in one line: only the facts that are known.
  const what = [
    device.model,
    device.osVersion ? `${t(`fleet.family.${device.family}`)} ${device.osVersion}` : t(`fleet.family.${device.family}`),
    t(`fleet.brand.${device.brand}`),
  ].filter((v): v is string => !!v);

  const link = 'inline-flex items-center gap-1 text-accent hover:underline';
  const muted = 'inline-flex items-center gap-1 text-text-muted';

  return (
    <header className="mb-5 rounded-lg border border-border bg-bg-secondary p-4">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div className="flex min-w-0 items-start gap-3">
          <div className="flex h-11 w-11 shrink-0 items-center justify-center rounded-xl bg-accent/10">
            {device.role === 'concentrator'
              ? <Radio size={22} className="text-accent" />
              : <Router size={22} className="text-accent" />}
          </div>
          <div className="min-w-0">
            <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
              <h1 className="flex min-w-0 items-center gap-2 text-xl font-semibold text-text-primary sm:text-2xl">
                <PresenceDot presence={presence} size={10} />
                <span className="truncate">{anonHostname(device.name)}</span>
              </h1>
              <span className={cn(
                'inline-flex items-center rounded-full border px-2 py-0.5 text-[10px] font-medium',
                deviceStatusStyle(device.status),
              )}>
                {t(`fleet.status.${device.status}`)}
              </span>
              <span className="rounded-full border border-border bg-bg-tertiary px-2 py-0.5 text-[10px] text-text-muted">
                {t(`fleet.role.${device.role}`)}
              </span>
              {/* Opened from the god view: whose device this is (the server
                  names the tenant on a god-view read only). */}
              <TenantBadge name={device.tenantName} className="text-[11px]" />
              {/* Learning mode: template pushes are refused on this router. */}
              {device.learning && (
                <span
                  className="rounded-full border border-accent/40 bg-accent/15 px-2 py-0.5 text-[10px] font-medium text-accent"
                  title={t('learning.refusalHint')}
                >
                  {t('learning.badge')}
                </span>
              )}
              {readOnly && (
                <span className="rounded-full border border-border bg-bg-tertiary px-2 py-0.5 text-[10px] text-text-muted">
                  {t('devices.readOnlyBadge')}
                </span>
              )}
            </div>
            <p className="mt-1 text-sm text-text-secondary">{what.join(' · ')}</p>
            <p className="mt-1 flex flex-wrap items-center gap-x-4 gap-y-1 text-[13px]">
              {device.siteId !== null
                ? (
                  <span className="inline-flex items-center gap-1.5">
                    <Link to={`/sites/${device.siteId}`} className={link} title={t('devices.fields.site')}>
                      <MapPin size={13} />{siteName}
                    </Link>
                    {/* « Ouvert / Fermé maintenant » (opening hours, migration 096). */}
                    <SiteOpenStateInline siteId={device.siteId} />
                  </span>
                )
                : <span className={cn(muted, 'italic')}><MapPin size={13} />{t('fleet.unassignedSite')}</span>}
              {device.groupId !== null && (
                <Link to={`/group/${device.groupId}`} className={link} title={t('devices.fields.group')}>
                  <Users size={13} />{device.groupName ?? `#${device.groupId}`}
                </Link>
              )}
              {device.concentratorId !== null && (
                <Link to={`/devices/${device.concentratorId}`} className={link} title={t('devices.fields.concentrator')}>
                  <Radio size={13} />{device.concentratorName ?? `#${device.concentratorId}`}
                </Link>
              )}
            </p>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-2">{actions}</div>
      </div>

      <div className="mt-3 border-t border-border pt-3">
        <DeviceStatusChips device={device} presence={presence} sources={sources} onSelect={onSelect} />
      </div>
    </header>
  );
}
