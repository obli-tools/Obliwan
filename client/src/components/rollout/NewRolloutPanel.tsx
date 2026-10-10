import { useCallback, useEffect, useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import {
  AlertTriangle,
  ArrowLeft,
  Calculator,
  Rocket,
  Search,
  ServerCrash,
  ShieldX,
  X,
} from 'lucide-react';
import type { ChangeJobKind, Wan1Mode } from '@obliwan/shared';
import { devicesApi } from '@/api/devices.api';
import { rolloutApi } from '@/api/rollout.api';
import type { RolloutConfig } from '@/api/rollout.api';
import { templatesApi, type Template, type TemplateRevision } from '@/api/templates.api';
import { errorMessageOf } from '@/api/change.api';
import { useChangeStore } from '@/store/changeStore';
import { useAuthStore } from '@/store/authStore';
import { Button } from '@/components/common/Button';
import { LoadingSpinner } from '@/components/common/LoadingSpinner';
import { TenantBadge } from '@/components/common/TenantBadge';
import { WaveCompositionList } from './WaveComposition';
import {
  buildManagementAccessRadius,
  managementAccessApi,
  type ManagementAccessComposition,
} from '@/components/fleet/managementAccess.api';
import { legacyComplianceApi } from '@/components/fleet/legacyCompliance.api';
import { wanLinkApi } from '@/components/fleet/wanLink.api';
import { anonHostname } from '@/utils/anonymize';
import { cn } from '@/utils/cn';
import type { Device } from '@/types/fleet';
import type { ImpactRadius, RolloutView } from '@/types/rollout';

/**
 * `management_access` (api-ssl on routers in service) has its own door: the
 * server composes it (`POST /devices/management-access/preview`) with ITS wave
 * ladder and launches it (`/devices/management-access/rollouts`) only for the
 * ladder shown — so for that kind the radius and the waves come from the
 * server, the ladder inputs do not apply, and devices the server refuses are
 * listed apart with its own sentence. It needs no change executor (the job is
 * a branch of its own), so the executor readiness does not block it.
 */
const MANAGEMENT_ACCESS: ChangeJobKind = 'management_access';
/** `legacy_compliance` (the corrected-template fixes on routers in service)
 *  takes the same kind of door: `/devices/legacy-compliance/preview|rollouts`. */
const LEGACY_COMPLIANCE: ChangeJobKind = 'legacy_compliance';
/** `wan_link` (the WAN1 link of each store switched to ONE mode, its
 *  parameters read from each site's variables) takes the same kind of door:
 *  `/devices/wan-link/preview|rollouts`, with the target mode in the body. */
const WAN_LINK: ChangeJobKind = 'wan_link';
const WAN_TARGET_MODES: readonly Wan1Mode[] = ['dhcp', 'pppoe', 'static'];
/**
 * The only kinds a rollout door accepts. A template `push` goes through
 * `/rollouts` (server-composed since the 400 fix: preview → compose → launch);
 * the two above have their own doors. export / backup / restore / reboot /
 * firmware are single-device jobs no door composes, and os_upgrade has
 * `/fleet-upgrade`.
 */
const ROLLOUT_KINDS: readonly ChangeJobKind[] = ['push', MANAGEMENT_ACCESS, LEGACY_COMPLIANCE, WAN_LINK];

/**
 * The impact-radius screen "compilation des N plans AVANT lancement".
 *
 * ┌─ THE ORDER OF THE THREE STEPS IS THE FEATURE ────────────────────────────┐
 * │ 1. pick the devices                                                      │
 * │ 2. COMPUTE — compile every plan, ask the preview for every safety net    │
 * │    and every Management-Path Guard verdict                               │
 * │ 3. read the composition, then launch                                     │
 * │                                                                          │
 * │ Step 2 is not optional and its result is not cached across a change of   │
 * │ device set: the Launch button does not exist until a radius has been     │
 * │ computed for exactly the set that is about to be launched. The           │
 * │ safety-net rule says the level is shown "AVANT le lancement, jamais      │
 * │ après", and a stale radius from a previous selection is an "après"       │
 * │ wearing an "avant" costume.                                              │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * The two confirmations below are NOT client-side politeness. The safety-net rule requires an
 * explicit recorded confirmation for a DEGRADED net, and a non-ACCEPT guard
 * verdict — INDETERMINATE included — requires a signed override. Both are sent
 * in the launch request; the server re-checks them and refuses the row if they
 * are not enough. A client-side gate is a convenience, a CHECK constraint is
 * the guarantee.
 */

const selectClass =
  'rounded-md border border-border bg-bg-tertiary px-2.5 py-1.5 text-[13px] text-text-primary focus:outline-none focus:ring-1 focus:ring-accent';

export function NewRolloutPanel({
  config,
  onCancel,
  onLaunched,
  initialKind,
  initialDeviceIds,
}: {
  config: RolloutConfig;
  onCancel: () => void;
  onLaunched: (rollout: RolloutView) => void;
  /** Opened from another page with a kind already chosen (the Sites page's
   *  « Changer le lien WAN… »). Only a kind a rollout door accepts is kept. */
  initialKind?: ChangeJobKind;
  /** …and routers already ticked. */
  initialDeviceIds?: readonly number[];
}) {
  const { t } = useTranslation();
  const writesAllowed = useChangeStore((s) => s.writesAllowed);
  const killSwitch = useChangeStore((s) => s.killSwitch);

  const [devices, setDevices] = useState<Device[]>([]);
  const [devicesLoading, setDevicesLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [selected, setSelected] = useState<Set<number>>(() => new Set(initialDeviceIds ?? []));

  const [name, setName] = useState('');
  const [kind, setKind] = useState<ChangeJobKind>(
    initialKind && ROLLOUT_KINDS.includes(initialKind) ? initialKind : 'push',
  );
  /** wan_link only: the mode every site switches to. */
  const [wanTargetMode, setWanTargetMode] = useState<Wan1Mode>('pppoe');
  /** push only: the template, and the ONE published revision pinned for every
   *  wave (the server recompiles each wave against it). */
  const [templates, setTemplates] = useState<Template[] | null>(null);
  const [templateId, setTemplateId] = useState<string>('');
  const [revisions, setRevisions] = useState<TemplateRevision[] | null>(null);
  const [revisionId, setRevisionId] = useState<number | null>(null);

  const [radius, setRadius] = useState<ImpactRadius | null>(null);
  /** The exact set the radius was computed for. A radius is only valid for the
   *  set it was computed against — see the block comment above. */
  const [radiusKey, setRadiusKey] = useState<string>('');
  const [computing, setComputing] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const [degradedConfirmed, setDegradedConfirmed] = useState(false);
  const [overrideReason, setOverrideReason] = useState('');
  const [launching, setLaunching] = useState(false);
  /** The devices the server refused, with its sentence. They are left out of
   *  the launch, and the operator acknowledges it explicitly. */
  const [refused, setRefused] = useState<ManagementAccessComposition['failures']>([]);
  const [refusedAck, setRefusedAck] = useState(false);
  const isManagementAccess = kind === MANAGEMENT_ACCESS;
  const isLegacyCompliance = kind === LEGACY_COMPLIANCE;
  const isWanLink = kind === WAN_LINK;
  const isPush = kind === 'push';

  useEffect(() => {
    let cancelled = false;
    void (async () => {
      try {
        const rows = await devicesApi.list();
        // A rollout writes to every router it holds: only the routers the
        // caller's teams may WRITE (`access`, migration 087) are offered. The
        // server refuses a mixed set anyway (403/404 on the compose).
        const writable = useAuthStore.getState().canWriteObject;
        if (!cancelled) setDevices(rows.filter((d) => writable(d)));
      } catch (err) {
        if (!cancelled) setError(errorMessageOf(err) ?? t('rollout.new.devicesFailed'));
      } finally {
        if (!cancelled) setDevicesLoading(false);
      }
    })();
    return () => { cancelled = true; };
  }, [t]);

  // push: the templates, loaded once (the tenant's and the shipped library).
  useEffect(() => {
    if (!isPush || templates !== null) return;
    let cancelled = false;
    void (async () => {
      try {
        const rows = await templatesApi.list({ includeLibrary: true });
        if (!cancelled) setTemplates(rows.filter((tpl) => tpl.status !== 'archived'));
      } catch (err) {
        if (!cancelled) {
          setTemplates([]);
          setError(errorMessageOf(err) ?? t('rollout.new.computeFailed'));
        }
      }
    })();
    return () => { cancelled = true; };
  }, [isPush, templates, t]);

  // push: the chosen template's PUBLISHED revisions, the highest by default.
  useEffect(() => {
    setRevisions(null);
    setRevisionId(null);
    if (!templateId) return;
    let cancelled = false;
    void (async () => {
      try {
        const rows = (await templatesApi.revisions(templateId))
          .filter((r) => r.status === 'published')
          .sort((a, b) => b.revision - a.revision);
        if (cancelled) return;
        setRevisions(rows);
        setRevisionId(rows.length > 0 ? Number(rows[0].id) : null);
      } catch (err) {
        if (!cancelled) {
          setRevisions([]);
          setError(errorMessageOf(err) ?? t('rollout.new.computeFailed'));
        }
      }
    })();
    return () => { cancelled = true; };
  }, [templateId, t]);

  const selectedIds = useMemo(() => [...selected].sort((a, b) => a - b), [selected]);
  const currentKey = useMemo(
    () => `${kind}:${isPush ? revisionId ?? '-' : isWanLink ? wanTargetMode : ''}:${selectedIds.join(',')}`,
    [kind, isPush, isWanLink, wanTargetMode, revisionId, selectedIds],
  );
  const radiusIsStale = radius !== null && radiusKey !== currentKey;

  const filtered = useMemo(() => {
    const needle = search.trim().toLowerCase();
    return devices
      .filter((d) => !needle || [d.name, d.siteName, d.model, d.brand]
        .filter(Boolean)
        .some((v) => String(v).toLowerCase().includes(needle)))
      .sort((a, b) => a.name.localeCompare(b.name));
  }, [devices, search]);

  // God view: the list spans every tenant (rows carry their tenant's name),
  // and a rollout is ONE tenant's — the server composes it in its routers'
  // tenant and refuses a set spanning several. Once a router is ticked, the
  // other tenants' rows are locked; "select all" never mixes tenants.
  const godViewRows = useMemo(() => devices.some((d) => d.tenantName !== undefined), [devices]);
  const lockedTenant = useMemo(() => {
    if (!godViewRows) return null;
    return devices.find((d) => selected.has(d.id))?.tenantId ?? null;
  }, [devices, selected, godViewRows]);
  const shownTenants = useMemo(() => new Set(filtered.map((d) => d.tenantId)), [filtered]);
  const selectAllTenant = !godViewRows
    ? null
    : lockedTenant ?? (shownTenants.size === 1 ? [...shownTenants][0] : undefined);
  const lockedOut = (d: Device) =>
    lockedTenant !== null && d.tenantId !== lockedTenant && !selected.has(d.id);

  // push: the templates that can apply to the ticked routers — their brand
  // (a template with no brand fits any) and, in the god view, their client's
  // own templates or the shipped library. The server refuses any other
  // revision ("does not exist in this tenant").
  const selectedBrands = useMemo(
    () => new Set(devices.filter((d) => selected.has(d.id)).map((d) => d.brand)),
    [devices, selected],
  );
  const shownTemplates = useMemo(() => {
    return (templates ?? []).filter((tpl) => {
      if (tpl.brand && selectedBrands.size > 0 && (selectedBrands.size > 1 || !selectedBrands.has(tpl.brand))) {
        return false;
      }
      if (godViewRows && lockedTenant !== null && !tpl.isLibrary && tpl.tenantId !== lockedTenant) return false;
      return true;
    });
  }, [templates, selectedBrands, godViewRows, lockedTenant]);
  // A template that no longer fits the selection is unselected, not kept.
  useEffect(() => {
    if (templateId && templates !== null && !shownTemplates.some((tpl) => tpl.id === templateId)) {
      setTemplateId('');
    }
  }, [templateId, templates, shownTemplates]);

  const toggle = useCallback((id: number) => {
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id); else next.add(id);
      return next;
    });
  }, []);

  const compute = useCallback(async () => {
    if (selectedIds.length === 0) return;
    if (isPush && revisionId === null) return;
    setComputing(true);
    setError(null);
    try {
      // One server call for every kind: the composition the launch will be
      // held to — its waves, its verdicts, the devices it refuses. A push is
      // compiled against the ONE revision that will be pushed, not against
      // each router's assignment.
      const pinned = revisionId;
      const ma = await buildManagementAccessRadius(
        selectedIds,
        devices,
        isPush && pinned !== null
          ? { preview: (ids) => rolloutApi.previewPush(ids, pinned, name), refusedBlocker: null }
          : isLegacyCompliance
            ? { preview: (ids) => legacyComplianceApi.preview(ids), refusedBlocker: null }
            : isWanLink
              ? { preview: (ids) => wanLinkApi.preview(ids, wanTargetMode, name), refusedBlocker: null }
              : { refusedBlocker: null },
      );
      setRefused(ma.refused);
      setRadius(ma.radius);
      setRadiusKey(currentKey);
      // A fresh radius invalidates whatever was confirmed against the old one.
      setDegradedConfirmed(false);
      setOverrideReason('');
      setRefusedAck(false);
    } catch (err) {
      setError(errorMessageOf(err) ?? t('rollout.new.computeFailed'));
    } finally {
      setComputing(false);
    }
  }, [selectedIds, isPush, isLegacyCompliance, isWanLink, wanTargetMode, revisionId, name, currentKey, devices, t]);

  // Always the server's waves: they are the only ones it will run.
  const waves = useMemo(() => radius?.waves ?? [], [radius]);

  const needsDegradedConfirmation = (radius?.degradedCount ?? 0) > 0;
  const needsOverride = (radius?.guardRefusedCount ?? 0) > 0;

  const blockers = useMemo(() => {
    const list: string[] = [];
    if (!radius) return list;
    for (const b of radius.blockers) list.push(t(`rollout.new.blocker.${b}`, { defaultValue: b }));
    if (radiusIsStale) list.push(t('rollout.new.blocker.STALE_RADIUS'));
    if (!name.trim()) list.push(t('rollout.new.blocker.NO_NAME'));
    if (isPush && revisionId === null) list.push(t('rollout.new.blocker.NO_REVISION'));
    if (!config.canLaunch && isPush) {
      list.push(t('rollout.new.blocker.ENDPOINT_ABSENT', { milestone: config.milestone ?? 'M7' }));
    }
    if (killSwitch.blocked) list.push(t('rollout.new.blocker.KILL_SWITCH'));
    if (!writesAllowed()) list.push(t('rollout.new.blocker.WRITES_DISABLED'));
    if (refused.length > 0 && !refusedAck) list.push(t('rollout.new.blocker.REFUSED_UNACKNOWLEDGED'));
    if (needsDegradedConfirmation && !degradedConfirmed) {
      list.push(t('rollout.new.blocker.DEGRADED_UNCONFIRMED'));
    }
    if (needsOverride && overrideReason.trim().length < 8) {
      list.push(t('rollout.new.blocker.OVERRIDE_REQUIRED'));
    }
    return list;
  }, [
    radius, radiusIsStale, name, isPush, revisionId, config, killSwitch.blocked, writesAllowed,
    refused.length, refusedAck, needsDegradedConfirmation, degradedConfirmed, needsOverride, overrideReason, t,
  ]);

  const launch = useCallback(async () => {
    if (!radius || blockers.length > 0) return;
    setLaunching(true);
    setError(null);
    try {
      // Only the composed targets are sent: the refused ones were acknowledged.
      const deviceIds = radius.rows.map((r) => r.deviceId);
      if (!isPush) {
        // Its own door; the degraded confirmation above is what the server's
        // `confirmNoDeadman` (`confirmExpectedCut` for wan_link) carries, and
        // the ladder sent is the one shown.
        const ladder = waves.map((w) => ({ size: w.rows.length }));
        const out = isWanLink
          ? await wanLinkApi.launchRollout({ name: name.trim(), deviceIds, toMode: wanTargetMode, waves: ladder })
          : await (isLegacyCompliance ? legacyComplianceApi : managementAccessApi).launchRollout({
            name: name.trim(),
            deviceIds,
            waves: ladder,
          });
        const launchedRollout = await rolloutApi.get(out.rolloutId);
        if (launchedRollout === null) {
          setError(t('rollout.new.launchEndpointAbsent'));
          return;
        }
        onLaunched(launchedRollout);
        return;
      }
      if (revisionId === null) return;
      // 1. Compose the DRAFT from the same body the preview answered.
      const composed = await rolloutApi.compose({
        name: name.trim(),
        deviceIds,
        templateRevisionId: revisionId,
        ...(needsOverride ? { overrideReason: overrideReason.trim() } : {}),
        ...(needsDegradedConfirmation ? { confirmDegraded: true } : {}),
      });
      // 2. The draft must be the composition the operator read. Anything else
      //    (a router refused since, a safety net that changed the order) is
      //    aborted — the draft holds its routers — and the screen says so.
      const shown = new Map<number, number>();
      for (const w of waves) for (const r of w.rows) shown.set(r.deviceId, w.index);
      const same =
        composed.targets.length === shown.size &&
        composed.targets.every((tg) => shown.get(tg.deviceId) === tg.waveIndex);
      if (!same) {
        try {
          await rolloutApi.abort(composed.rolloutId, 'composition changed since the impact screen');
        } catch {
          /* the error below is the one the operator needs */
        }
        setRadiusKey('');
        setError(t('rollout.new.compositionChanged'));
        return;
      }
      // 3. Launch it.
      await rolloutApi.start(composed.rolloutId);
      const launchedRollout = await rolloutApi.get(composed.rolloutId);
      if (launchedRollout === null) {
        setError(t('rollout.new.launchEndpointAbsent'));
        return;
      }
      onLaunched(launchedRollout);
    } catch (err) {
      setError(errorMessageOf(err) ?? t('rollout.new.launchFailed'));
    } finally {
      setLaunching(false);
    }
  }, [
    radius, blockers, name, isPush, revisionId, waves, needsDegradedConfirmation, needsOverride, isLegacyCompliance,
    isWanLink, wanTargetMode, overrideReason, onLaunched, t,
  ]);

  return (
    <div className="space-y-4">
      <button
        onClick={onCancel}
        className="inline-flex items-center gap-1.5 text-sm text-text-muted hover:text-text-primary"
      >
        <ArrowLeft size={14} /> {t('rollout.new.back')}
      </button>

      {/* ── step 1: what, and on which boxes ── */}
      <section className="rounded-lg border border-border bg-bg-secondary p-4">
        <h2 className="text-sm font-semibold text-text-primary">{t('rollout.new.step1')}</h2>
        <p className="mb-3 text-[12px] text-text-muted">{t('rollout.new.step1Hint')}</p>

        <div className="mb-3 flex flex-wrap items-end gap-3">
          <label className="block">
            <span className="mb-1 block text-[11px] uppercase tracking-wider text-text-muted">
              {t('rollout.new.name')}
            </span>
            <input
              type="text"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder={t('rollout.new.namePlaceholder')}
              className="w-72 rounded-md border border-border bg-bg-tertiary px-2.5 py-1.5 text-[13px] text-text-primary placeholder:text-text-muted focus:outline-none focus:ring-1 focus:ring-accent"
            />
          </label>

          <label className="block">
            <span className="mb-1 block text-[11px] uppercase tracking-wider text-text-muted">
              {t('rollout.new.kind')}
            </span>
            <select
              className={selectClass}
              value={kind}
              onChange={(e) => setKind(e.target.value as ChangeJobKind)}
            >
              {/* Only the kinds a rollout door accepts (ROLLOUT_KINDS above). */}
              {ROLLOUT_KINDS.map((k) => (
                <option key={k} value={k}>{t(`change.kind.${k}`, { defaultValue: k })}</option>
              ))}
            </select>
          </label>

          {isPush && (
            <>
              <label className="block">
                <span className="mb-1 block text-[11px] uppercase tracking-wider text-text-muted">
                  {t('rollout.new.template')}
                </span>
                <select
                  className={cn(selectClass, 'max-w-[18rem]')}
                  value={templateId}
                  onChange={(e) => setTemplateId(e.target.value)}
                  disabled={templates === null}
                >
                  <option value="">—</option>
                  {shownTemplates.map((tpl) => (
                    <option key={tpl.id} value={tpl.id}>
                      {tpl.name}
                      {tpl.isLibrary ? ' · lib' : ''}
                      {tpl.brand ? ` · ${tpl.brand}` : ''}
                    </option>
                  ))}
                </select>
              </label>

              <label className="block">
                <span className="mb-1 block text-[11px] uppercase tracking-wider text-text-muted">
                  {t('rollout.new.revision')}
                </span>
                <select
                  className={selectClass}
                  value={revisionId ?? ''}
                  onChange={(e) => setRevisionId(e.target.value ? Number(e.target.value) : null)}
                  disabled={!templateId || revisions === null || revisions.length === 0}
                >
                  {(revisions ?? []).length === 0 && <option value="">—</option>}
                  {(revisions ?? []).map((r) => (
                    <option key={r.id} value={Number(r.id)}>
                      r{r.revision}
                      {r.publishedAt ? ` · ${new Date(r.publishedAt).toLocaleDateString()}` : ''}
                    </option>
                  ))}
                </select>
              </label>
              {templateId && revisions !== null && revisions.length === 0 && (
                <p className="w-full text-[12px] text-status-ssl-warning">{t('rollout.new.noPublishedRevision')}</p>
              )}
            </>
          )}

          <p className="w-full text-[12px] text-text-muted">
            {t('rollout.new.serverWaves')} {t('rollout.new.gatePolicyManualRestore')}
          </p>
          {isManagementAccess && (
            <p className="w-full text-[12px] text-text-muted">
              {t('rollout.new.managementAccessHint', {
                defaultValue:
                  'Opens api-ssl (8729, management range only, a certificate made on the router) on each router in service, ' +
                  'over SSH, one job per router. The waves are the server\'s ladder (canary first, behind the health gate); ' +
                  'no dead-man is armed, a pre-change backup is taken before each first write. Where a router lacks ' +
                  'ObliWAN\'s own "obliwan" account, the job creates it and switches ObliWAN to it once a login with it is ' +
                  'proven. Where the "obliwan" group ObliWAN made lacks only the "sensitive" policy, the job adds it — the ' +
                  'one existing account or group it changes — through the historical "admin" account from the vault ' +
                  '(admin_password) on a router already reached as "obliwan"; without that credential, a router with ' +
                  'nothing else to write succeeds and says the group is not aligned; one where api-ssl must still be ' +
                  'written fails at its pre-change backup (nothing is written) until the group is aligned.',
              })}
            </p>
          )}
          {isLegacyCompliance && (
            <p className="w-full text-[12px] text-text-muted">{t('rollout.new.legacyComplianceHint')}</p>
          )}
          {isWanLink && (
            <>
              <label className="block">
                <span className="mb-1 block text-[11px] uppercase tracking-wider text-text-muted">
                  {t('rollout.new.wanTargetMode')}
                </span>
                <select
                  className={selectClass}
                  value={wanTargetMode}
                  onChange={(e) => setWanTargetMode(e.target.value as Wan1Mode)}
                >
                  {WAN_TARGET_MODES.map((m) => (
                    <option key={m} value={m}>{t(`wanLink.mode.${m}`)}</option>
                  ))}
                </select>
              </label>
              <p className="w-full text-[12px] text-text-muted">{t('rollout.new.wanLinkHint')}</p>
            </>
          )}
        </div>

        <div className="mb-2 flex flex-wrap items-center gap-2">
          <div className="relative">
            <Search size={13} className="pointer-events-none absolute left-2.5 top-1/2 -translate-y-1/2 text-text-muted" />
            <input
              type="text"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder={t('rollout.new.searchPlaceholder')}
              className="w-64 rounded-md border border-border bg-bg-tertiary py-1.5 pl-8 pr-2.5 text-[13px] text-text-primary placeholder:text-text-muted focus:outline-none focus:ring-1 focus:ring-accent"
            />
          </div>
          <button
            onClick={() => setSelected(new Set(
              filtered.filter((d) => selectAllTenant === null || d.tenantId === selectAllTenant).map((d) => d.id),
            ))}
            disabled={selectAllTenant === undefined}
            title={selectAllTenant === undefined ? t('rollout.new.oneTenantHint') : undefined}
            className="rounded-md border border-border bg-bg-tertiary px-2 py-1.5 text-[12px] text-text-secondary hover:bg-bg-hover disabled:cursor-not-allowed disabled:opacity-50"
          >
            {t('rollout.new.selectAll')}
          </button>
          {selected.size > 0 && (
            <button
              onClick={() => setSelected(new Set())}
              className="inline-flex items-center gap-1 rounded-md px-2 py-1.5 text-[12px] text-text-muted hover:bg-bg-hover hover:text-text-primary"
            >
              <X size={12} /> {t('devices.filters.clear')}
            </button>
          )}
          <span className="ml-auto font-mono text-[11px] text-text-muted">
            {t('rollout.new.selectedCount', { count: selected.size })}
          </span>
        </div>

        {godViewRows && shownTenants.size > 1 && (
          <p className="mb-2 text-[11px] text-text-muted">{t('rollout.new.oneTenantHint')}</p>
        )}

        {devicesLoading ? (
          <div className="flex justify-center py-8"><LoadingSpinner /></div>
        ) : (
          <div className="max-h-64 overflow-y-auto rounded-md border border-border">
            <table className="w-full text-left text-[13px]">
              <tbody className="divide-y divide-border">
                {filtered.map((d) => (
                  <tr key={d.id} className={cn('hover:bg-bg-hover', lockedOut(d) && 'opacity-40')}>
                    <td className="w-8 px-2 py-1.5">
                      <input
                        type="checkbox"
                        checked={selected.has(d.id)}
                        disabled={lockedOut(d)}
                        title={lockedOut(d) ? t('rollout.new.oneTenantHint') : undefined}
                        onChange={() => toggle(d.id)}
                        className="accent-accent"
                      />
                    </td>
                    <td className="px-2 py-1.5 text-text-primary">{anonHostname(d.name)}</td>
                    {godViewRows && (
                      <td className="px-2 py-1.5"><TenantBadge name={d.tenantName} tenantId={d.tenantId} /></td>
                    )}
                    <td className="px-2 py-1.5 text-[11px] text-text-muted">{d.siteName ?? '—'}</td>
                    <td className="px-2 py-1.5 font-mono text-[11px] text-text-muted">{d.brand}</td>
                    <td className="px-2 py-1.5 font-mono text-[11px] text-text-muted">
                      {d.role === 'concentrator' ? t('rollout.new.roleConcentrator') : ''}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      {/* ── step 2: compute ── */}
      <section className="rounded-lg border border-border bg-bg-secondary p-4">
        <h2 className="text-sm font-semibold text-text-primary">{t('rollout.new.step2')}</h2>
        <p className="mb-3 text-[12px] text-text-muted">{t('rollout.new.step2Hint')}</p>
        <div className="flex flex-wrap items-center gap-3">
          <Button
            variant="secondary"
            size="sm"
            disabled={selectedIds.length === 0 || computing || (isPush && revisionId === null)}
            loading={computing}
            onClick={() => void compute()}
          >
            <Calculator size={14} className="mr-1.5" />
            {t('rollout.new.compute')}
          </Button>
          {isPush && revisionId === null && (
            <span className="text-[12px] text-text-muted">{t('rollout.new.blocker.NO_REVISION')}</span>
          )}
          {radiusIsStale && (
            <span className="inline-flex items-center gap-1.5 rounded border border-status-ssl-warning/50 bg-status-ssl-warning/10 px-2 py-1 text-[12px] text-status-ssl-warning">
              <AlertTriangle size={12} />
              {t('rollout.new.staleRadius')}
            </span>
          )}
        </div>
      </section>

      {error && (
        <div className="rounded-lg border border-status-ssl-expired/40 bg-status-ssl-expired/5 p-3 text-sm text-status-ssl-expired">
          {error}
        </div>
      )}

      {/* ── step 3: the radius, the waves, the confirmations ── */}
      {radius && (
        <>
          <section className="grid grid-cols-2 gap-3 md:grid-cols-5">
            <Tile label={t('rollout.impact.devices')} value={String(radius.rows.length)} tone="muted" />
            <Tile
              label={t('rollout.impact.degraded')}
              value={String(radius.degradedCount)}
              tone={radius.degradedCount > 0 ? 'bad' : 'ok'}
              hint={t('rollout.impact.degradedHint')}
            />
            <Tile
              label={t('rollout.impact.guardRefused')}
              value={String(radius.guardRefusedCount)}
              tone={radius.guardRefusedCount > 0 ? 'bad' : 'ok'}
              hint={t('rollout.impact.guardRefusedHint')}
            />
            <Tile
              label={t('rollout.impact.concentrators')}
              value={String(radius.concentratorCount)}
              tone={radius.concentratorCount > 0 ? 'bad' : 'muted'}
              hint={t('rollout.impact.concentratorsHint')}
            />
            <Tile
              label={t('rollout.impact.subtreeSites')}
              value={String(radius.subtreeSiteCount)}
              tone={radius.subtreeSiteCount > 0 ? 'bad' : 'muted'}
              hint={t('rollout.impact.subtreeSitesHint')}
            />
          </section>

          {/* The sentence that is NOT in the safety-net table. */}
          {radius.concentratorCount > 0 && (
            <div className="rounded-lg border border-status-ssl-expired/50 bg-status-ssl-expired/10 p-3">
              <p className="flex items-start gap-2 text-[13px] text-status-ssl-expired">
                <AlertTriangle size={15} className="mt-0.5 shrink-0" />
                {t('rollout.impact.concentratorWarning', { sites: radius.subtreeSiteCount })}
              </p>
              <p className="mt-1 pl-6 text-[12px] text-status-ssl-expired">
                {t('rollout.impact.concentratorRecovery')}
              </p>
            </div>
          )}

          {radius.warnings.length > 0 && (
            <div className="rounded-lg border border-status-ssl-warning/40 bg-status-ssl-warning/5 p-3 text-[12px] text-status-ssl-warning">
              {radius.warnings.map((w) => (
                <p key={w} className="font-mono">{t(`rollout.new.warning.${w}`, { defaultValue: w })}</p>
              ))}
            </div>
          )}

          {/* The routers the server refused, in its words. They are left out of the
              launch, and the operator says so explicitly. */}
          {refused.length > 0 && (
            <div className="rounded-lg border border-status-ssl-expired/50 bg-status-ssl-expired/10 p-3">
              <p className="mb-1 flex items-center gap-1.5 text-[13px] font-medium text-status-ssl-expired">
                <AlertTriangle size={14} />
                {t('rollout.new.managementAccessRefused', { count: refused.length })}
              </p>
              <ul className="space-y-1 pl-5 text-[12px] text-text-secondary">
                {refused.map((f) => (
                  <li key={f.deviceId}>
                    <span className="font-medium text-text-primary">{anonHostname(f.deviceName ?? `#${f.deviceId}`)}</span>
                    {' — '}
                    {f.message}
                  </li>
                ))}
              </ul>
              <label className="mt-2 flex cursor-pointer items-center gap-2 text-[12px] text-text-primary">
                <input
                  type="checkbox"
                  checked={refusedAck}
                  onChange={(e) => setRefusedAck(e.target.checked)}
                  className="accent-red-500"
                />
                {t('rollout.new.refusedAck', { count: refused.length })}
              </label>
            </div>
          )}

          <WaveCompositionList waves={waves} />

          {/* ── the two confirmations the safety-net rule requires ── */}
          {needsDegradedConfirmation && (
            <label className="flex cursor-pointer items-start gap-2 rounded-lg border border-status-ssl-expired/50 bg-status-ssl-expired/10 p-3">
              <input
                type="checkbox"
                checked={degradedConfirmed}
                onChange={(e) => setDegradedConfirmed(e.target.checked)}
                className="mt-0.5 accent-red-500"
              />
              <span>
                <span className="flex items-center gap-1.5 text-[13px] font-medium text-status-ssl-expired">
                  <ServerCrash size={14} />
                  {t('rollout.new.degradedConfirm', { count: radius.degradedCount })}
                </span>
                <span className="mt-0.5 block text-[12px] text-status-ssl-expired">
                  {isWanLink ? t('rollout.new.wanLinkCutConfirmHint') : t('rollout.new.degradedConfirmHint')}
                </span>
              </span>
            </label>
          )}

          {needsOverride && (
            <div className="rounded-lg border border-status-ssl-expired/50 bg-status-ssl-expired/10 p-3">
              <p className="flex items-center gap-1.5 text-[13px] font-medium text-status-ssl-expired">
                <ShieldX size={14} />
                {t('rollout.new.overrideTitle', { count: radius.guardRefusedCount })}
              </p>
              <p className="mt-0.5 text-[12px] text-status-ssl-expired">
                {t('rollout.new.overrideHint')}
              </p>
              <textarea
                value={overrideReason}
                onChange={(e) => setOverrideReason(e.target.value)}
                rows={2}
                placeholder={t('rollout.new.overridePlaceholder')}
                className="mt-2 w-full rounded-md border border-border bg-bg-tertiary px-2.5 py-1.5 text-[13px] text-text-primary placeholder:text-text-muted focus:outline-none focus:ring-1 focus:ring-accent"
              />
            </div>
          )}

          <section className="rounded-lg border border-border bg-bg-secondary p-4">
            {blockers.length > 0 && (
              <ul className="mb-3 space-y-1">
                {blockers.map((b) => (
                  <li key={b} className="flex items-start gap-1.5 text-[12px] text-status-ssl-expired">
                    <AlertTriangle size={12} className="mt-0.5 shrink-0" />
                    {b}
                  </li>
                ))}
              </ul>
            )}

            <Button
              variant="danger"
              disabled={blockers.length > 0 || launching}
              loading={launching}
              onClick={() => void launch()}
            >
              <Rocket size={15} className="mr-1.5" />
              {t('rollout.new.launch', { count: radius.rows.length, waves: waves.length })}
            </Button>
          </section>
        </>
      )}
    </div>
  );
}

const TONES = {
  ok: 'text-status-up',
  bad: 'text-status-ssl-expired',
  muted: 'text-text-primary',
};

function Tile({
  label,
  value,
  tone,
  hint,
}: {
  label: string;
  value: string;
  tone: keyof typeof TONES;
  hint?: string;
}) {
  return (
    <div className="rounded-lg border border-border bg-bg-secondary p-3" title={hint}>
      <div className="text-[11px] uppercase tracking-wider text-text-muted">{label}</div>
      <div className={cn('mt-1 font-display text-xl font-semibold tabular-nums', TONES[tone])}>
        {value}
      </div>
    </div>
  );
}
