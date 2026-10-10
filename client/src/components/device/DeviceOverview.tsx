import { useEffect, useRef, useState, type ReactNode } from 'react';
import { Link } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { Antenna, ArrowRight, FileCode, Fingerprint, Globe, GraduationCap, KeyRound, ListChecks, Network, Smartphone, StickyNote } from 'lucide-react';
import {
  CAPABILITIES,
  DEVICE_MODE_MAX_AGE_DAYS,
  deadmanReadiness,
  type DeviceHealthCheckView,
} from '@obliwan/shared';
import { useAuthStore } from '@/store/authStore';
import { Button } from '@/components/common/Button';
import { Hint } from '@/components/ui/Hint';
import { VerdictBadge } from '@/components/fleet/VerdictBadge';
import { HealthCheckPanel } from '@/components/fleet/HealthCheckPanel';
import { AutoConfirmPanel } from '@/components/fleet/AutoConfirmPanel';
import { ConcentratorLinkCard } from '@/components/fleet/ConcentratorLinkCard';
import { ManagementAccessCard } from '@/components/fleet/ManagementAccessCard';
import { LegacyComplianceCard } from '@/components/fleet/LegacyComplianceCard';
import { WanLinkCard } from '@/components/fleet/WanLinkCard';
import { SiteRenameSection } from '@/components/fleet/SiteRenameCard';
import { LearningCard } from '@/components/fleet/LearningCard';
import { DeviceTemplateCard } from '@/components/fleet/DeviceTemplateCard';
import { DeviceUplinkCard } from '@/components/telemetry/DeviceUplinkCard';
import { LineQualitySection } from '@/components/telemetry/LineQualityCard';
import { VerdictBadge as SimVerdictBadge } from '@/components/mobile/SimBits';
import { ZoneUsageLine } from '@/components/mobile/ZoneUsage';
import { cn } from '@/utils/cn';
import { connStateStyle } from '@/utils/verdict';
import type { DeviceDetail, DeviceModeInfo, DevicePresence } from '@/types/fleet';
import {
  complianceSignal, healthSignal, managementSignal, presenceSignal, simNoLineReason,
  simSignal, templateSignal, uplinkSignal, wanLinkSignal, worstTone, type SimState,
} from './deviceSignals';
import type { DeviceSignalReporters, DeviceSignalSources } from './useDeviceSignals';
import type { DeviceTabId, OverviewSectionId, SectionFocus } from './devicePage';
import { StatusSection } from './StatusSection';

/**
 * The overview tab of a device page.
 *
 * ┌─ READING ORDER ───────────────────────────────────────────────────────────┐
 * │ 1. « Identité & raccordement »: what the box is, where it belongs and how │
 * │    it is reached — a compact spec sheet, always open, every field it ever │
 * │    had (nothing was dropped in the redesign: ObliWAN keeps all the facts).│
 * │ 2. « État »: one collapsible section per topic, each with a one-line      │
 * │    answer. A topic with a problem is unfolded, a healthy one folded; the  │
 * │    rationale stays behind « Pourquoi ? » as before.                      │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * The cards inside the sections are the existing ones, drawn `embedded` and
 * reporting what they loaded through `onView`: the header chips and the
 * section summaries read those reports, so nothing is fetched twice and a
 * summary cannot contradict the card under it.
 */

// ── Identity & attachment ───────────────────────────────────────────────────

function Row({ label, children, mono }: { label: string; children: ReactNode; mono?: boolean }) {
  const empty = children === null || children === undefined || children === '';
  return (
    <div className="flex items-baseline justify-between gap-3 py-1.5">
      <dt className="shrink-0 text-xs text-text-muted">{label}</dt>
      <dd className={cn('min-w-0 break-words text-right text-[13px] text-text-primary', mono && 'font-mono text-[12px]')}>
        {empty ? <span className="text-text-muted">—</span> : children}
      </dd>
    </div>
  );
}

function Group({ title, children, hint }: { title: string; children: ReactNode; hint?: ReactNode }) {
  return (
    <div className="min-w-0">
      <h3 className="mb-1 text-[11px] font-semibold uppercase tracking-wider text-text-muted">{title}</h3>
      <dl className="divide-y divide-border/60">{children}</dl>
      {hint}
    </div>
  );
}

/**
 * RouterOS device-mode, with what it MEANS: "home" alone tells an operator
 * nothing; what it tells him is that this router cannot carry a dead-man, so a
 * change on it is unguarded and no credential or job will fix that — somebody
 * has to press reset in front of the box. The verdict is `deadmanReadiness()`'s,
 * the one the server reads too. MikroTik only: a "—" on a DrayTek would imply
 * a concept that platform does not have.
 */
function DeviceModeRows({ reading }: { reading: DeviceModeInfo | null }) {
  const { t } = useTranslation();
  const { feasibility, stale, ageDays } = deadmanReadiness(reading);
  const tone = feasibility === 'blocked' ? 'text-status-down'
    : feasibility === 'capable' ? 'text-status-up'
      : 'text-status-ssl-warning';
  // `unread` is where every device starts; `notExposed` means the menu was
  // asked and said nothing, which is NOT "this firmware has no gate".
  const label = reading === null ? t('devices.deviceMode.unread')
    : reading.mode === null ? t('devices.deviceMode.notExposed')
      : t(`devices.deviceMode.mode.${reading.mode}`, { defaultValue: reading.mode });
  return (
    <>
      <Row label={t('devices.fields.deviceMode')}><span className={tone}>{label}</span></Row>
      <Row label={t('devices.fields.deviceModeRead')}>
        {reading === null ? null : (
          <span className={stale ? 'text-status-ssl-warning' : undefined}>
            {new Date(reading.observedAt).toLocaleDateString()}
            {stale && ageDays !== null
              && ` · ${t('devices.deviceMode.stale', { days: Math.round(ageDays), max: DEVICE_MODE_MAX_AGE_DAYS })}`}
          </span>
        )}
      </Row>
    </>
  );
}

/** The equipment group's « Pourquoi ? »: the identity rationale and, on a
 *  MikroTik, what its device-mode means. A BLOCKED device-mode is not
 *  rationale but a consequence the operator must see, so it stays unfolded. */
function EquipmentNotes({ device }: { device: DeviceDetail }) {
  const { t } = useTranslation();
  const mikrotik = device.brand === 'mikrotik';
  const { feasibility } = deadmanReadiness(device.deviceMode);
  return (
    <>
      {mikrotik && feasibility === 'blocked' && (
        <p className="mt-2 max-w-prose text-xs text-status-down">{t('devices.deviceMode.blockedHint')}</p>
      )}
      <Hint className="mt-2">
        {mikrotik && feasibility !== 'blocked' && (
          <span className="mb-1.5 block">
            {feasibility === 'capable' ? t('devices.deviceMode.capableHint') : t('devices.deviceMode.unknownHint')}
          </span>
        )}
        {t('devices.identityHint')}
      </Hint>
    </>
  );
}

function IdentityCard({
  device,
  presence,
  siteName,
  focusNonce,
}: {
  device: DeviceDetail;
  presence: DevicePresence | null;
  siteName: string | null;
  focusNonce: number;
}) {
  const { t } = useTranslation();
  const ref = useRef<HTMLElement>(null);
  useEffect(() => {
    if (focusNonce !== 0) ref.current?.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }, [focusNonce]);
  const when = (iso: string | null) => (iso ? new Date(iso).toLocaleString() : null);

  return (
    <section ref={ref} className="scroll-mt-4 rounded-lg border border-border bg-bg-secondary p-4">
      <h2 className="mb-3 flex items-center gap-2 text-sm font-semibold text-text-primary">
        <Fingerprint size={15} className="text-text-secondary" />
        {t('devices.page.identityTitle')}
      </h2>
      <div className="grid grid-cols-1 gap-x-8 gap-y-5 md:grid-cols-2 xl:grid-cols-3">
        <Group
          title={t('devices.page.identity.device')}
          hint={<EquipmentNotes device={device} />}
        >
          <Row label={t('devices.fields.brand')}>{t(`fleet.brand.${device.brand}`)}</Row>
          <Row label={t('devices.fields.family')}>{t(`fleet.family.${device.family}`)}</Row>
          <Row label={t('devices.fields.model')}>{device.model}</Row>
          <Row label={t('devices.fields.osVersion')} mono>{device.osVersion}</Row>
          <Row label={t('devices.fields.serial')} mono>{device.serial}</Row>
          <Row label={t('devices.fields.systemIdentity')} mono>{device.systemIdentity}</Row>
          <Row label={t('devices.fields.pppUsername')} mono>{device.pppUsername}</Row>
          {device.brand === 'mikrotik' && <DeviceModeRows reading={device.deviceMode} />}
          <Row label={t('devices.fields.uuid')} mono><span className="break-all">{device.uuid}</span></Row>
        </Group>

        <Group title={t('devices.sections.placement')}>
          <Row label={t('devices.fields.site')}>
            {device.siteId !== null
              ? <Link to={`/sites/${device.siteId}`} className="text-accent hover:underline">{siteName}</Link>
              : <span className="italic text-text-muted">{t('fleet.unassignedSite')}</span>}
          </Row>
          <Row label={t('devices.fields.group')}>
            {device.groupId !== null
              ? <Link to={`/group/${device.groupId}`} className="text-accent hover:underline">{device.groupName ?? `#${device.groupId}`}</Link>
              : null}
          </Row>
          <Row label={t('devices.fields.concentrator')}>
            {device.concentratorId !== null
              ? (
                <Link to={`/devices/${device.concentratorId}`} className="text-accent hover:underline">
                  {device.concentratorName ?? `#${device.concentratorId}`}
                </Link>
              )
              : <span className="italic text-text-muted">{t('devices.noConcentrator')}</span>}
          </Row>
          <Row label={t('devices.fields.managed')}>{device.isManaged ? t('fleet.yes') : t('fleet.no')}</Row>
          <Row label={t('devices.fields.firstSeen')}>{when(device.firstSeenAt)}</Row>
          <Row label={t('devices.fields.lastSeen')}>{when(device.lastSeenAt)}</Row>
        </Group>

        <Group
          title={t('devices.page.identity.addressing')}
          hint={<Hint className="mt-2">{t('devices.addressingHint')}</Hint>}
        >
          <Row label={t('devices.fields.pppState')}>
            {/* A device with no concentrator has no tunnel to cut: presence
                comes from the CHR's `/ppp/active`, and a standalone
                device is not in that list because it was never meant to be.
                Reading `false` as "down" there manufactured an alarm on every
                direct-attached router. */}
            {device.concentratorId === null
              ? <span className="italic text-text-muted">{t('fleet.presenceNotApplicable')}</span>
              : presence == null || presence.up === null
                ? <span className="italic text-text-muted">{t('fleet.presenceUnknown')}</span>
                : presence.up
                  ? <span className="text-status-up">{t('fleet.presenceUp')}</span>
                  : <span className="text-status-down">{t('fleet.presenceDown')}</span>}
          </Row>
          <Row label={t('fleet.lastChange')}>{when(presence?.at ?? null)}</Row>
          <Row label={t('devices.fields.tunnelIp')} mono>{presence?.tunnelIp ?? device.tunnelIp}</Row>
          <Row label={t('devices.fields.wanPublicIp')} mono>{presence?.callerIp ?? device.wanPublicIp}</Row>
          <Row label={t('devices.fields.sourceIpHint')} mono>{device.sourceIpHint}</Row>
        </Group>
      </div>
    </section>
  );
}

// ── SIM summary (the « 4G / SIM » tab holds the rest) ───────────────────────

function SimSummary({ sim, onOpenTab }: { sim: SimState; onOpenTab: (tab: DeviceTabId) => void }) {
  const { t } = useTranslation();
  const open = (
    <Button size="sm" variant="secondary" onClick={() => onOpenTab('sim')}>
      {t('devices.sim.openTab')}
      <ArrowRight size={14} className="ml-1.5" />
    </Button>
  );
  if (sim.status !== 'ready') {
    return (
      <div className="space-y-3">
        <p className="text-sm text-text-muted">{sim.status === 'error' ? t('simBlock.loadError') : '…'}</p>
        {open}
      </div>
    );
  }
  const { view } = sim;
  return (
    <div className="space-y-3">
      {view.lines.length > 0 ? (
        <ul className="space-y-2">
          {view.lines.map((l) => (
            <li key={l.id} className="flex flex-wrap items-center gap-x-4 gap-y-2 text-sm">
              <Link to={`/mobile/lines/${l.id}`} className="font-mono text-accent hover:underline">{l.msisdn}</Link>
              <span className="text-text-secondary">{l.operator ?? t('mobile.noOperator')}</span>
              <SimVerdictBadge verdict={l.verdict} stale={l.stale} />
              <ZoneUsageLine
                usage={l.worstUsage}
                thresholdPercent={l.thresholdPercent}
                thresholdMb={l.thresholdMb}
                compact
              />
            </li>
          ))}
        </ul>
      ) : (
        <p className="text-sm text-text-secondary">{t(`devices.sim.reason.${simNoLineReason(view)}`)}</p>
      )}
      {view.modems.length > 0 && (
        <p className="text-xs text-text-muted">
          {t('devices.sim.modemsRead', { count: view.modems.length, names: view.modems.map((m) => m.interface).join(', ') })}
        </p>
      )}
      {open}
    </div>
  );
}

// ── The tab ─────────────────────────────────────────────────────────────────

export function DeviceOverview({
  device,
  presence,
  siteName,
  canWrite,
  sources,
  report,
  focus,
  onHealthChecked,
  onReload,
  onOpenTab,
}: {
  device: DeviceDetail;
  presence: DevicePresence | null;
  siteName: string | null;
  canWrite: boolean;
  sources: DeviceSignalSources;
  report: DeviceSignalReporters;
  focus: SectionFocus | null;
  onHealthChecked: (view: DeviceHealthCheckView) => void;
  onReload: () => void;
  onOpenTab: (tab: DeviceTabId) => void;
}) {
  const { t } = useTranslation();
  const isAdmin = useAuthStore((s) => s.isAdmin)();
  const hasCapability = useAuthStore((s) => s.hasCapability);
  const isConcentrator = device.role === 'concentrator';
  const isMikrotikCpe = device.brand === 'mikrotik' && !isConcentrator;
  const canApplyChange = isAdmin || hasCapability(CAPABILITIES.CHANGE_APPLY);
  const canReadTemplate = isAdmin || hasCapability(CAPABILITIES.TEMPLATE_READ);
  const canWriteTemplate = isAdmin || hasCapability(CAPABILITIES.TEMPLATE_WRITE);
  const nonce = (section: OverviewSectionId) => (focus?.section === section ? focus.nonce : 0);

  // Reachability: the reachability verdict, the permanent check and the channels'
  // circuit breakers, judged together.
  const presenceSig = presenceSignal(t, presence?.verdict);
  const healthSig = healthSignal(t, device.healthCheck);
  const health = device.health ?? [];
  const reachTone = worstTone(presenceSig.tone, healthSig.tone, health.some((h) => h.connState === 'down') ? 'warn' : null);

  const management = managementSignal(t, sources.management);
  const compliance = complianceSignal(t, sources.compliance);
  const wanLink = wanLinkSignal(t, sources.wanLink);
  // The WAN link card's « open the template fixes » (DNS-Amp) scrolls there.
  const [complianceNudge, setComplianceNudge] = useState(0);
  const canChangeWan = canApplyChange && (isAdmin || hasCapability(CAPABILITIES.SITE_VARIABLES_WRITE));
  const uplink = uplinkSignal(t, sources.uplink);
  const sim = simSignal(t, sources.sim);
  const template = templateSignal(t, sources.template);

  return (
    <div className="space-y-4">
      {/* The CHR's WireGuard link to ObliWAN: platform admins only (the CHR is shared). */}
      {isConcentrator && isAdmin && <ConcentratorLinkCard deviceId={device.id} />}

      <IdentityCard device={device} presence={presence} siteName={siteName} focusNonce={nonce('identity')} />

      <h2 className="pt-2 text-[11px] font-semibold uppercase tracking-wider text-text-muted">
        {t('devices.page.stateTitle')}
      </h2>

      <StatusSection
        title={t('devices.sections.reachability')}
        icon={<Network size={15} />}
        tone={reachTone}
        summary={t('devices.page.reachSummary', { presence: presenceSig.value, health: healthSig.value })}
        focusNonce={nonce('reachability')}
      >
        <div className="space-y-4">
          <VerdictBadge verdict={presence?.verdict ?? null} withHint />
          {/* The permanent check sits under the verdict it feeds: on a
              concentrator, its fresh answer is what turns the verdict back to
              UP. "Check now" reloads the page so the verdict shown is the one
              the check just wrote. */}
          <HealthCheckPanel
            deviceId={device.id}
            view={device.healthCheck}
            canCheck={canWrite}
            onChecked={onHealthChecked}
          />
          <AutoConfirmPanel deviceId={device.id} canRecheck={canWrite} onConfirmed={onReload} />
          <div>
            <h3 className="mb-2 text-[11px] font-semibold uppercase tracking-wider text-text-muted">
              {t('devices.sections.transportHealth')}
            </h3>
            {health.length === 0 ? (
              <p className="text-sm text-text-muted">{t('devices.noHealth')}</p>
            ) : (
              <ul className="space-y-2">
                {health.map((h) => (
                  <li key={h.transport} className="flex flex-wrap items-center gap-2 text-sm">
                    <span className="w-24 font-mono text-[12px] text-text-secondary">
                      {t(`fleet.transport.${h.transport}`)}
                    </span>
                    <span className={cn(
                      'inline-flex items-center rounded-full border px-2 py-0.5 text-[10px] font-medium',
                      connStateStyle(h.connState),
                    )}>
                      {t(`fleet.connState.${h.connState}`)}
                    </span>
                    <span className="text-[11px] text-text-muted">{t(`fleet.circuit.${h.circuitState}`)}</span>
                    {h.lastRttMs != null && <span className="font-mono text-[11px] text-text-muted">{h.lastRttMs} ms</span>}
                    {h.lastError && <span className="break-all font-mono text-[11px] text-text-muted">{h.lastError}</span>}
                  </li>
                ))}
              </ul>
            )}
          </div>
        </div>
      </StatusSection>

      {isMikrotikCpe && (
        <StatusSection
          title={t('managementAccess.title')}
          icon={<KeyRound size={15} />}
          tone={management?.tone ?? 'info'}
          summary={management?.value ?? t('managementAccess.state.unsupported')}
          focusNonce={nonce('management')}
        >
          <ManagementAccessCard deviceId={device.id} canLaunch={canApplyChange} embedded onView={report.management} />
        </StatusSection>
      )}

      {/* The corrected customer templates, applied by a legacy_compliance job.
          Drawn nothing (but kept mounted) on a router the job does not cover. */}
      {isMikrotikCpe && (
        <StatusSection
          title={t('legacyCompliance.title')}
          icon={<ListChecks size={15} />}
          tone={compliance?.tone ?? 'info'}
          summary={compliance?.value ?? ''}
          hidden={compliance === null}
          focusNonce={nonce('compliance') + complianceNudge}
        >
          <LegacyComplianceCard deviceId={device.id} canLaunch={canApplyChange} embedded onView={report.compliance} />
        </StatusSection>
      )}

      {/* Renaming the site's router (login on the shared CHR, management tunnel,
          identity, site code): platform admins only — the job writes on the CHR. */}
      {isMikrotikCpe && isAdmin && <SiteRenameSection deviceId={device.id} />}

      {/* Learning mode: platform admins only, like its API (requireRole('admin')). */}
      {isMikrotikCpe && isAdmin && (
        <StatusSection
          title={t('learning.title')}
          icon={<GraduationCap size={15} />}
          tone={device.learning ? 'warn' : 'info'}
          summary={device.learning ? t('learning.badge') : t('learning.off')}
        >
          <LearningCard deviceId={device.id} learning={device.learning ?? null} onChanged={onReload} />
        </StatusSection>
      )}

      {/* The WAN1 link (box DHCP / PPPoE / fixed IP), switched by a wan_link job. */}
      {isMikrotikCpe && (
        <StatusSection
          title={t('wanLink.title')}
          icon={<Globe size={15} />}
          tone={wanLink?.tone ?? 'info'}
          summary={wanLink?.value ?? ''}
          hidden={wanLink === null}
        >
          <WanLinkCard
            deviceId={device.id}
            canLaunch={canChangeWan}
            embedded
            onView={report.wanLink}
            onOpenCompliance={() => setComplianceNudge((n) => n + 1)}
          />
        </StatusSection>
      )}

      <StatusSection
        title={t('uplink.title')}
        icon={<Antenna size={15} />}
        tone={uplink.tone}
        summary={uplink.value}
        focusNonce={nonce('uplink')}
      >
        {sources.uplink === null && <p className="text-sm text-text-muted">{t('devices.page.uplinkUnreadable')}</p>}
        <DeviceUplinkCard deviceId={device.id} embedded onView={report.uplink} />
      </StatusSection>

      {/* The fixed line measured each night outside opening hours (migration 097). */}
      {isMikrotikCpe && <LineQualitySection deviceId={device.id} />}

      {/* The SIM in its modem and the mobile line it feeds: the summary
          here, everything else in the « 4G / SIM » tab. */}
      {!isConcentrator && sim !== null && (
        <StatusSection
          title={t('devices.sim.tab')}
          icon={<Smartphone size={15} />}
          tone={sim.tone}
          summary={sim.value}
          focusNonce={nonce('sim')}
        >
          <SimSummary sim={sources.sim} onOpenTab={onOpenTab} />
        </StatusSection>
      )}

      {/* The revision this device's previews and plans render — a bench
          router is pinned to the one it was compiled with. */}
      {isMikrotikCpe && canReadTemplate && (
        <StatusSection
          title={t('deviceTemplate.title', { defaultValue: 'Template' })}
          icon={<FileCode size={15} />}
          tone={template.tone}
          summary={template.value}
          focusNonce={nonce('template')}
        >
          <DeviceTemplateCard deviceId={device.id} canWrite={canWriteTemplate} embedded onView={report.template} />
        </StatusSection>
      )}

      {device.notes && (
        <section className="rounded-lg border border-border bg-bg-secondary p-4">
          <h2 className="mb-2 flex items-center gap-2 text-sm font-semibold text-text-primary">
            <StickyNote size={15} className="text-text-secondary" />
            {t('devices.fields.notes')}
          </h2>
          <p className="whitespace-pre-wrap text-sm text-text-secondary">{device.notes}</p>
        </section>
      )}
    </div>
  );
}
