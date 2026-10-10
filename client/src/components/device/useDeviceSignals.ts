import { useCallback, useEffect, useRef, useState } from 'react';
import { simApi } from '@/api/sim.api';
import { driftApi } from '@/api/drift.api';
import type { DeviceTemplateResolution } from '@/api/templates.api';
import type { ManagementAccessView } from '@/components/fleet/managementAccess.api';
import type { LegacyComplianceView } from '@/components/fleet/legacyCompliance.api';
import type { WanLinkView } from '@/components/fleet/wanLink.api';
import type { UplinkVerdict } from '@/components/telemetry/DeviceUplinkCard';
import type { DriftState, Loaded, SimState } from './deviceSignals';

/**
 * Where the device page's status chips read from.
 *
 * Two kinds of source, and the split is deliberate:
 *
 * - REPORTED: management access, compliance, uplink and template are loaded
 *   by their own cards (which poll, and reload after their own buttons) and
 *   handed up through `onView`. The overview that holds those cards stays
 *   mounted while another tab is shown, so the chips keep a live source and
 *   nothing is fetched twice.
 * - FETCHED HERE: the SIM view and the last drift run have no card on the
 *   overview to report them — the SIM view feeds both the overview's summary
 *   and the « 4G / SIM » tab, so it is read once, here.
 *
 * Every source starts `undefined` (loading) for each device: the page is not
 * remounted when it navigates from a router to its concentrator, and the
 * previous router's answers must not stand for the next one.
 */
export interface DeviceSignalSources {
  management: Loaded<ManagementAccessView>;
  compliance: Loaded<LegacyComplianceView>;
  /** Reported by the WAN link card. */
  wanLink: Loaded<WanLinkView>;
  uplink: Loaded<UplinkVerdict>;
  template: Loaded<DeviceTemplateResolution>;
  sim: SimState;
  drift: DriftState;
}

/** Stable setters, safe to pass as `onView`. */
export interface DeviceSignalReporters {
  management: (view: ManagementAccessView | null) => void;
  compliance: (view: LegacyComplianceView | null) => void;
  wanLink: (view: WanLinkView | null) => void;
  uplink: (view: UplinkVerdict | null) => void;
  template: (view: DeviceTemplateResolution | null) => void;
}

export function useDeviceSignals(
  deviceId: number | null,
  opts: { simReadable: boolean; configReadable: boolean },
): { sources: DeviceSignalSources; report: DeviceSignalReporters; reloadSim: () => void } {
  const { simReadable, configReadable } = opts;
  const [management, setManagement] = useState<Loaded<ManagementAccessView>>(undefined);
  const [compliance, setCompliance] = useState<Loaded<LegacyComplianceView>>(undefined);
  const [wanLink, setWanLink] = useState<Loaded<WanLinkView>>(undefined);
  const [uplink, setUplink] = useState<Loaded<UplinkVerdict>>(undefined);
  const [template, setTemplate] = useState<Loaded<DeviceTemplateResolution>>(undefined);
  const [sim, setSim] = useState<SimState>({ status: 'off' });
  const [drift, setDrift] = useState<DriftState>({ status: 'off' });
  const [simNonce, setSimNonce] = useState(0);

  // A new device: forget everything the previous one reported.
  useEffect(() => {
    setManagement(undefined);
    setCompliance(undefined);
    setWanLink(undefined);
    setUplink(undefined);
    setTemplate(undefined);
  }, [deviceId]);

  // The device the SIM view on screen belongs to: a reload of the same device
  // keeps it on screen while the new one is read, another device never does.
  const simFor = useRef<number | null>(null);
  useEffect(() => {
    if (deviceId === null || !simReadable) { setSim({ status: 'off' }); simFor.current = null; return; }
    let live = true;
    if (simFor.current !== deviceId) setSim({ status: 'loading' });
    simApi.deviceSim(deviceId)
      .then((view) => { if (live) { simFor.current = deviceId; setSim({ status: 'ready', view }); } })
      .catch(() => { if (live) { simFor.current = null; setSim({ status: 'error' }); } });
    return () => { live = false; };
  }, [deviceId, simReadable, simNonce]);

  useEffect(() => {
    if (deviceId === null || !configReadable) { setDrift({ status: 'off' }); return; }
    let live = true;
    setDrift({ status: 'loading' });
    driftApi.forDevice(deviceId, 1)
      // `null`: this build does not serve the drift routes — no chip at all.
      .then((runs) => { if (live) setDrift(runs === null ? { status: 'off' } : { status: 'ready', last: runs[0] ?? null }); })
      .catch(() => { if (live) setDrift({ status: 'error' }); });
    return () => { live = false; };
  }, [deviceId, configReadable]);

  const reloadSim = useCallback(() => setSimNonce((n) => n + 1), []);

  return {
    sources: { management, compliance, wanLink, uplink, template, sim, drift },
    report: { management: setManagement, compliance: setCompliance, wanLink: setWanLink, uplink: setUplink, template: setTemplate },
    reloadSim,
  };
}
