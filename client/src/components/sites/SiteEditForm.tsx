import { useCallback, useEffect, useMemo, useState, type FormEvent } from 'react';
import { Lock, Trash2, X } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import toast from 'react-hot-toast';
import type { ApiResponse } from '@obliwan/shared';
import apiClient from '@/api/client';
import { Button } from '@/components/common/Button';
import { Input } from '@/components/common/Input';
import { LoadingSpinner } from '@/components/common/LoadingSpinner';
import { cn } from '@/utils/cn';
import { weekdayNames } from '@/utils/maintenance';
import { SiteUplinkSelect, choiceOf, kindOf, type SiteUplinkChoice } from '@/components/sites/SiteUplink';
import type { MaintenanceWindow, Site } from '@/types/fleet';

// ============================================================================
// The site's edit context — GET /sites/:id/edit-context
// ============================================================================

/** Mirror of `SiteCodeLockReason` (server/src/services/fleet/site.service.ts). */
export type SiteCodeLockReason = 'allocation' | 'bench';
/** Mirror of `SITE_DELETE_ACKNOWLEDGEMENTS` (server/src/validators/site.schema.ts). */
export type SiteDeleteAcknowledgement = 'chr_account' | 'bench_history' | 'sla_history';
/** Mirror of `ChrAccountBasis` (server/src/services/fleet/site.service.ts):
 *  the first two are certain, the last two are "may be there". */
export type ChrAccountBasis = 'provisioned' | 'adopted' | 'job_running' | 'add_unconfirmed';

export interface SiteAllocationSummary {
  pppUsername: string;
  tunnelIp: string;
  lanSubnet: string | null;
  concentratorState: string;
  source: 'allocated' | 'adopted_chr' | null;
}

export interface SiteDeleteImpact {
  devicesDetached: number;
  allocationReleased: SiteAllocationSummary | null;
  /** The L2TP account that stays, or may stay, on the concentrator: ObliWAN never removes one. */
  chrAccountKept: { pppUsername: string; tunnelIp: string; basis: ChrAccountBasis } | null;
  benchHistoryKept: number;
  /** Deleted with the site. */
  slaReportsDeleted: number;
  slaObjectivesDeleted: number;
  /** What the delete must acknowledge by name. */
  acknowledge: SiteDeleteAcknowledgement[];
}

export interface SiteEditContext {
  siteId: number;
  /** The site DTO does not carry the country; this does. */
  country: string | null;
  /** Empty = the code may still change. */
  codeLock: SiteCodeLockReason[];
  allocation: SiteAllocationSummary | null;
  benchProvisionings: number;
  deletion: SiteDeleteImpact;
}

const CODE_LOCK_REASONS: readonly string[] = ['allocation', 'bench'];
const ACKNOWLEDGEMENTS: readonly string[] = ['chr_account', 'bench_history', 'sla_history'];
const CHR_BASES: readonly string[] = ['provisioned', 'adopted', 'job_running', 'add_unconfirmed'];

/** A "may be there" account (a job adding it, an add whose answer was lost). */
function chrAccountUncertain(kept: { basis: ChrAccountBasis } | null | undefined): boolean {
  return kept?.basis === 'job_running' || kept?.basis === 'add_unconfirmed';
}

function str(v: unknown): string | null {
  return typeof v === 'string' ? v : null;
}
function num(v: unknown): number {
  const n = typeof v === 'number' ? v : Number(v);
  return Number.isFinite(n) && n >= 0 ? n : 0;
}

function normalizeAllocation(raw: unknown): SiteAllocationSummary | null {
  if (!raw || typeof raw !== 'object') return null;
  const r = raw as Record<string, unknown>;
  const login = str(r.pppUsername);
  const tunnel = str(r.tunnelIp);
  if (!login || !tunnel) return null;
  return {
    pppUsername: login,
    tunnelIp: tunnel,
    lanSubnet: str(r.lanSubnet),
    concentratorState: str(r.concentratorState) ?? '',
    source: r.source === 'allocated' || r.source === 'adopted_chr' ? r.source : null,
  };
}

function normalizeImpact(raw: unknown): SiteDeleteImpact | null {
  if (!raw || typeof raw !== 'object') return null;
  const r = raw as Record<string, unknown>;
  const kept = r.chrAccountKept as Record<string, unknown> | null | undefined;
  return {
    devicesDetached: num(r.devicesDetached),
    allocationReleased: normalizeAllocation(r.allocationReleased),
    chrAccountKept:
      kept && str(kept.pppUsername) && str(kept.tunnelIp)
        ? {
            pppUsername: kept.pppUsername as string,
            tunnelIp: kept.tunnelIp as string,
            // A server that predates `basis` reported only certain accounts.
            basis: CHR_BASES.includes(str(kept.basis) ?? '') ? (kept.basis as ChrAccountBasis) : 'provisioned',
          }
        : null,
    benchHistoryKept: num(r.benchHistoryKept),
    slaReportsDeleted: num(r.slaReportsDeleted),
    slaObjectivesDeleted: num(r.slaObjectivesDeleted),
    acknowledge: Array.isArray(r.acknowledge)
      ? (r.acknowledge.filter((a) => typeof a === 'string' && ACKNOWLEDGEMENTS.includes(a)) as SiteDeleteAcknowledgement[])
      : [],
  };
}

function normalizeContext(raw: unknown): SiteEditContext | null {
  if (!raw || typeof raw !== 'object') return null;
  const r = raw as Record<string, unknown>;
  const deletion = normalizeImpact(r.deletion);
  if (!deletion || !Array.isArray(r.codeLock)) return null;
  return {
    siteId: num(r.siteId),
    country: str(r.country),
    codeLock: r.codeLock.filter((c) => typeof c === 'string' && CODE_LOCK_REASONS.includes(c)) as SiteCodeLockReason[],
    allocation: normalizeAllocation(r.allocation),
    benchProvisionings: num(r.benchProvisionings),
    deletion,
  };
}

/**
 * `null` = the context could not be read (an older server without the route,
 * a network failure). Callers then FAIL CLOSED: the code stays read-only, the
 * country is not offered, and a delete names nothing — the server, which
 * judges again under its locks, refuses anything that needs acknowledging.
 */
export async function fetchSiteEditContext(siteId: number): Promise<SiteEditContext | null> {
  try {
    const res = await apiClient.get<ApiResponse<unknown>>(`/sites/${siteId}/edit-context`);
    return normalizeContext(res.data.data);
  } catch {
    return null;
  }
}

function errorOf(err: unknown): { status: number | null; message: string | null; details: Record<string, string[]> } {
  const response = (err as { response?: { status?: number; data?: { error?: unknown; details?: unknown } } }).response;
  const details: Record<string, string[]> = {};
  const raw = response?.data?.details;
  if (raw && typeof raw === 'object') {
    for (const [k, v] of Object.entries(raw as Record<string, unknown>)) {
      if (Array.isArray(v)) details[k] = v.filter((x): x is string => typeof x === 'string');
    }
  }
  return {
    status: typeof response?.status === 'number' ? response.status : null,
    message: typeof response?.data?.error === 'string' ? response.data.error : null,
    details,
  };
}

// ============================================================================
// Client-side checks — the creation rules (server/src/validators/site.schema.ts)
// ============================================================================

const CODE_MAX = 64;
const CODE_RE = /^[A-Za-z0-9][A-Za-z0-9._-]*$/;
const NAME_MAX = 255;
const ADDRESS_MAX = 2000;
const CONTACT_MAX = 500;
const TIMEZONE_MAX = 64;
const TIME_RE = /^([01]\d|2[0-3]):[0-5]\d$/;
const TIMEZONE_SHAPE = /^[A-Za-z][A-Za-z0-9_+-]*(\/[A-Za-z0-9_+-]+)*$/;

function isIanaTimeZone(tz: string): boolean {
  if (tz.length > TIMEZONE_MAX || !TIMEZONE_SHAPE.test(tz)) return false;
  try {
    new Intl.DateTimeFormat('en-US', { timeZone: tz });
    return true;
  } catch {
    return false;
  }
}

/** The allocator's rule: trimmed, empty = null, two letters, uppercase. */
function parseCountry(raw: string): { ok: true; value: string | null } | { ok: false } {
  const t = raw.trim();
  if (t === '') return { ok: true, value: null };
  return /^[A-Za-z]{2}$/.test(t) ? { ok: true, value: t.toUpperCase() } : { ok: false };
}

function timeZoneNames(): string[] {
  const intl = Intl as unknown as { supportedValuesOf?: (key: string) => string[] };
  try {
    return intl.supportedValuesOf?.('timeZone') ?? [];
  } catch {
    return [];
  }
}

type WindowShape = { days: number[]; start: string; end: string; tz: string } | null;

/** Two windows that the change scheduler would judge the same way. A stored
 *  window without `tz` is judged in the site's timezone (jobQueue.service). */
function sameWindow(next: WindowShape, current: MaintenanceWindow | null, currentTimezone: string): boolean {
  const hasCurrent = Boolean(current && ((current.days?.length ?? 0) > 0 || current.start || current.end));
  if (!next || !hasCurrent) return !next && !hasCurrent;
  const days = [...(current!.days ?? [])].sort((a, b) => a - b);
  return (
    JSON.stringify(days) === JSON.stringify(next.days) &&
    (current!.start ?? '') === next.start &&
    (current!.end ?? '') === next.end &&
    (current!.tz || currentTimezone) === next.tz
  );
}

type FieldKey = 'code' | 'name' | 'country' | 'address' | 'contact' | 'timezone' | 'window' | 'uplink' | 'fixedProvider';
/** « Opérateur du lien fixe » (migration 095): the server's bound. */
const FIXED_PROVIDER_MAX = 64;
const SERVER_FIELD: Record<string, FieldKey> = {
  code: 'code',
  name: 'name',
  country: 'country',
  address: 'address',
  contact: 'contact',
  timezone: 'timezone',
  maintenanceWindow: 'window',
  uplinkKind: 'uplink',
  fixedProvider: 'fixedProvider',
};

// ============================================================================
// The form
// ============================================================================

/**
 * Edit a site: name, code, country, address, contact, timezone, maintenance
 * window. Sends only what changed, so a field the operator did not touch is
 * never re-judged (a legacy code, a schedule this operator may not change).
 *
 * The code is offered only while the site has neither an allocation nor a
 * bench preparation (`context.codeLock` empty); the server refuses the rename
 * anyway under its locks. The schedule (timezone, window) needs
 * `canSchedule`: it decides when pushes may reach the site's routers.
 */
export function SiteEditForm({
  site,
  context,
  canSchedule,
  onSaved,
  onCancel,
}: {
  site: Site;
  context: SiteEditContext | null;
  canSchedule: boolean;
  onSaved: (site: Site) => void;
  onCancel: () => void;
}) {
  const { t, i18n } = useTranslation();
  const names = weekdayNames(i18n.language);
  const zones = useMemo(timeZoneNames, []);

  const codeLocked = context === null || context.codeLock.length > 0;
  const countryKnown = context !== null;
  /** The zone the stored window is judged in today: its own `tz` first, the
   *  site's timezone otherwise (jobQueue.service `isWithinMaintenanceWindow`). */
  const storedWindowTz = site.maintenanceWindow?.tz || site.timezone;
  const windowOwnTz = storedWindowTz !== site.timezone ? storedWindowTz : null;

  const [name, setName] = useState(site.name);
  const [code, setCode] = useState(site.code);
  const [country, setCountry] = useState(context?.country ?? '');
  const [address, setAddress] = useState(site.address ?? '');
  const [contact, setContact] = useState(site.contact ?? '');
  const [timezone, setTimezone] = useState(site.timezone);
  const [uplink, setUplink] = useState<SiteUplinkChoice>(choiceOf(site.uplinkKind));
  const [fixedProvider, setFixedProvider] = useState(site.fixedProvider ?? '');
  const [days, setDays] = useState<number[]>([...(site.maintenanceWindow?.days ?? [])].sort((a, b) => a - b));
  const [start, setStart] = useState(site.maintenanceWindow?.start ?? '');
  const [end, setEnd] = useState(site.maintenanceWindow?.end ?? '');
  const [errors, setErrors] = useState<Partial<Record<FieldKey, string>>>({});
  const [formError, setFormError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);

  // The context may arrive after the form opened.
  useEffect(() => {
    setCountry(context?.country ?? '');
  }, [context?.country]);

  const toggleDay = (day: number) =>
    setDays((prev) => (prev.includes(day) ? prev.filter((d) => d !== day) : [...prev, day].sort((a, b) => a - b)));

  const validate = (): Partial<Record<FieldKey, string>> => {
    const e: Partial<Record<FieldKey, string>> = {};
    const required = t('sites.edit.errors.required', { defaultValue: 'Required.' });
    const tooLong = (max: number) => t('sites.edit.errors.tooLong', { max, defaultValue: 'At most {{max}} characters.' });
    if (name.trim() === '') e.name = required;
    else if (name.trim().length > NAME_MAX) e.name = tooLong(NAME_MAX);
    if (!codeLocked) {
      const c = code.trim();
      if (c === '') e.code = required;
      else if (c.length > CODE_MAX) e.code = tooLong(CODE_MAX);
      else if (!CODE_RE.test(c)) {
        e.code = t('sites.edit.errors.codeShape', {
          defaultValue: 'Letters, digits, dot, dash and underscore only, starting with a letter or a digit.',
        });
      }
    }
    if (countryKnown && !parseCountry(country).ok) {
      e.country = t('sites.edit.errors.country', { defaultValue: 'Two letters (ISO 3166-1 alpha-2).' });
    }
    if (address.trim().length > ADDRESS_MAX) e.address = tooLong(ADDRESS_MAX);
    if (contact.trim().length > CONTACT_MAX) e.contact = tooLong(CONTACT_MAX);
    if (fixedProvider.trim().replace(/\s+/g, ' ').length > FIXED_PROVIDER_MAX) e.fixedProvider = tooLong(FIXED_PROVIDER_MAX);
    if (canSchedule) {
      if (!isIanaTimeZone(timezone.trim())) {
        e.timezone = t('sites.edit.errors.timezone', { defaultValue: 'An IANA time zone (e.g. Europe/Paris).' });
      }
      const empty = days.length === 0 && start === '' && end === '';
      if (!empty && (days.length === 0 || !TIME_RE.test(start) || !TIME_RE.test(end))) {
        e.window = t('sites.edit.errors.window', {
          defaultValue: 'Pick at least one day, a start and an end — or clear all three for no window.',
        });
      }
    }
    return e;
  };

  const buildBody = (): Record<string, unknown> => {
    const body: Record<string, unknown> = {};
    if (name.trim() !== site.name) body.name = name.trim();
    if (!codeLocked && code.trim() !== site.code) body.code = code.trim();
    if (countryKnown) {
      const c = parseCountry(country);
      if (c.ok && c.value !== context!.country) body.country = c.value;
    }
    const addr = address.trim() === '' ? null : address.trim();
    if (addr !== site.address) body.address = addr;
    const cont = contact.trim() === '' ? null : contact.trim();
    if (cont !== site.contact) body.contact = cont;
    // Sent only when it changes: restating it would not be a declaration.
    if (uplink !== choiceOf(site.uplinkKind)) body.uplinkKind = kindOf(uplink);
    // The server's normalisation (trim, inner spaces collapsed, '' = null).
    const provider = fixedProvider.trim().replace(/\s+/g, ' ');
    if ((provider === '' ? null : provider) !== (site.fixedProvider ?? null)) {
      body.fixedProvider = provider === '' ? null : provider;
    }
    if (canSchedule) {
      const tz = timezone.trim();
      const timezoneChanged = tz !== site.timezone;
      if (timezoneChanged) body.timezone = tz;
      // The window carries its zone, and the scheduler reads that zone before
      // the site's. It keeps the zone it is judged in today — its own `tz`,
      // which may differ from the site's — unless the operator changes the
      // site's timezone, which moves the window with it.
      const windowTz = timezoneChanged ? tz : storedWindowTz;
      const next: WindowShape =
        days.length === 0 && start === '' && end === '' ? null : { days, start, end, tz: windowTz };
      if (!sameWindow(next, site.maintenanceWindow, site.timezone)) body.maintenanceWindow = next;
    }
    return body;
  };

  const submit = async (ev: FormEvent) => {
    ev.preventDefault();
    setFormError(null);
    const e = validate();
    setErrors(e);
    if (Object.keys(e).length > 0) return;
    const body = buildBody();
    if (Object.keys(body).length === 0) {
      toast(t('sites.edit.nothingChanged', { defaultValue: 'Nothing changed.' }));
      onCancel();
      return;
    }
    setSaving(true);
    try {
      const res = await apiClient.patch<ApiResponse<Site>>(`/sites/${site.id}`, body);
      toast.success(t('sites.edit.saved', { defaultValue: 'Site saved' }));
      onSaved(res.data.data!);
    } catch (err) {
      const { message, details } = errorOf(err);
      const fieldErrors: Partial<Record<FieldKey, string>> = {};
      for (const [k, v] of Object.entries(details)) {
        const key = SERVER_FIELD[k];
        if (key && v.length > 0) fieldErrors[key] = v.join(' ');
      }
      setErrors(fieldErrors);
      setFormError(message ?? t('sites.edit.failed', { defaultValue: 'The site could not be saved.' }));
    } finally {
      setSaving(false);
    }
  };

  const lockReasons: string[] =
    context === null
      ? [t('sites.edit.codeLock.unknown', {
          defaultValue: 'Whether this site has an allocation or a bench preparation could not be read: the code stays read-only.',
        })]
      : context.codeLock.map((reason) =>
          reason === 'allocation'
            ? t('sites.edit.codeLock.allocation', {
                login: context.allocation?.pppUsername ?? '—',
                defaultValue:
                  'This site has an address allocation (PPP login {{login}}): its login and identity were computed from the site’s data, code included, and are frozen. The code itself and the derived values are read from the site again at every compile, so after a new code the two would no longer agree.',
              })
            : t('sites.edit.codeLock.bench', {
                count: context.benchProvisionings,
                defaultValue: 'The bench has already compiled {{count}} file(s) for this site with this code.',
              }),
        );
  // The one operation that unfreezes the code, and only while no bench file
  // exists (bench history is never removed).
  if (context !== null && context.codeLock.length === 1 && context.codeLock[0] === 'allocation') {
    lockReasons.push(
      t('sites.edit.codeLock.releaseHint', {
        defaultValue:
          'To change the code, a platform administrator first releases the allocation on the Allocation page (an allocation already provisioned asks for its login to be typed, and its account stays on the concentrator).',
      }),
    );
  }
  const frozenLogin = context?.allocation?.pppUsername ?? null;

  return (
    <section className="mb-4 rounded-lg border border-accent/40 bg-bg-secondary p-4">
      <div className="mb-3 flex items-center gap-2">
        <h2 className="flex-1 text-sm font-semibold uppercase tracking-wide text-text-secondary">
          {t('sites.edit.title', { defaultValue: 'Edit the site' })}
        </h2>
        <button
          type="button"
          onClick={onCancel}
          className="rounded p-1 text-text-muted hover:text-text-primary"
          aria-label={t('common.cancel')}
        >
          <X size={16} />
        </button>
      </div>

      <form onSubmit={submit} className="space-y-4" noValidate>
        {formError && (
          <p role="alert" className="rounded-md border border-status-down/40 bg-status-down/10 px-3 py-2 text-sm text-status-down">
            {formError}
          </p>
        )}

        <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
          <Input
            id="site-edit-name"
            label={t('sites.fields.name')}
            value={name}
            maxLength={NAME_MAX}
            error={errors.name}
            onChange={(e) => setName(e.target.value)}
          />
          <div className="space-y-1">
            <Input
              id="site-edit-code"
              label={t('sites.fields.code')}
              value={codeLocked ? site.code : code}
              readOnly={codeLocked}
              disabled={codeLocked}
              maxLength={CODE_MAX}
              error={errors.code}
              className="font-mono"
              onChange={(e) => setCode(e.target.value)}
            />
            {codeLocked && (
              <div className="flex items-start gap-1.5 text-xs text-text-muted">
                <Lock size={12} className="mt-0.5 shrink-0" />
                <div className="space-y-0.5">
                  {lockReasons.map((r) => <p key={r}>{r}</p>)}
                </div>
              </div>
            )}
          </div>
          <div className="space-y-1">
            <Input
              id="site-edit-country"
              label={t('sites.edit.fields.country', { defaultValue: 'Country' })}
              value={country}
              maxLength={2}
              disabled={!countryKnown}
              error={errors.country}
              className="font-mono uppercase"
              onChange={(e) => setCountry(e.target.value)}
            />
            <p className="text-xs text-text-muted">
              {countryKnown
                ? t('sites.edit.countryHint', { defaultValue: 'ISO 3166-1 code, two letters (FR, BE…). Empty = not stated.' })
                : t('sites.edit.countryUnknown', {
                    defaultValue: 'The stored country could not be read; it cannot be edited right now.',
                  })}
            </p>
          </div>
          {frozenLogin && (
            <p className="text-xs text-status-pending md:col-span-2">
              {t('sites.edit.allocationFrozen', {
                login: frozenLogin,
                defaultValue:
                  'This site has an allocation: its PPP login {{login}} and its identity are frozen and do not follow a change of name or country, while any value derived from the site’s data is recomputed from the new ones.',
              })}
            </p>
          )}
          <Input
            id="site-edit-contact"
            label={t('sites.fields.contact')}
            value={contact}
            maxLength={CONTACT_MAX}
            error={errors.contact}
            onChange={(e) => setContact(e.target.value)}
          />
          <div className="space-y-1">
            <label htmlFor="site-edit-uplink" className="block text-sm font-medium text-text-secondary">
              {t('sites.uplink.label', { defaultValue: 'Access link' })}
            </label>
            <SiteUplinkSelect id="site-edit-uplink" value={uplink} onChange={setUplink} />
            {errors.uplink && <p className="text-xs text-status-down">{errors.uplink}</p>}
            <p className="text-xs text-text-muted">
              {t('sites.uplink.hint', {
                defaultValue:
                  'Automatic: ObliWAN infers the link from the router. Fixed line + 4G backup: time on 4G is a backup, alerted after the delay. 4G only: 4G is the site’s nominal path — never a backup alert, never a fleet anomaly.',
              })}
            </p>
          </div>
          <div className="space-y-1">
            <Input
              id="site-edit-fixed-provider"
              label={t('operatorOutage.site.label', { defaultValue: 'Fixed-line provider' })}
              value={fixedProvider}
              maxLength={FIXED_PROVIDER_MAX}
              placeholder={t('operatorOutage.site.placeholder', { defaultValue: 'e.g. Orange, SFR, Bouygues Telecom, Free…' })}
              error={errors.fixedProvider}
              onChange={(e) => setFixedProvider(e.target.value)}
            />
            <p className="text-xs text-text-muted">
              {t('operatorOutage.site.hint', {
                defaultValue:
                  'Used to group stores falling back to 4G at the same time into one « probable operator outage » alert. Empty: inferred from the PPPoE login, the ASN or the public prefix of the fixed line.',
              })}
            </p>
          </div>
          <div className="md:col-span-2">
            <Input
              id="site-edit-address"
              label={t('sites.fields.address')}
              value={address}
              maxLength={ADDRESS_MAX}
              error={errors.address}
              onChange={(e) => setAddress(e.target.value)}
            />
          </div>
        </div>

        <fieldset className="space-y-3 rounded-md border border-border p-3" disabled={!canSchedule}>
          <legend className="px-1 text-xs font-semibold uppercase tracking-wide text-text-secondary">
            {t('sites.sections.maintenance')}
          </legend>
          <p className="text-xs text-text-muted">
            {canSchedule
              ? t('sites.edit.windowHint', {
                  defaultValue:
                    'Changes are pushed only inside this window, in its own time zone when it carries one, otherwise in the site’s. No window means no constraint: changes may be pushed at any time.',
                })
              : t('sites.edit.scheduleNeedsRight', {
                  defaultValue:
                    'Changing the time zone or the maintenance window takes the device-write right: they decide when pushes may reach this site’s routers.',
                })}
          </p>
          {windowOwnTz && (
            <p className="text-xs text-status-pending">
              {t('sites.edit.windowOwnTz', {
                tz: windowOwnTz,
                defaultValue:
                  'This window is judged in its own time zone, {{tz}}, not in the site’s. It keeps that zone unless the site’s time zone is changed here, which moves the window to the new one.',
              })}
            </p>
          )}
          <div>
            <Input
              id="site-edit-timezone"
              label={t('sites.fields.timezone')}
              value={timezone}
              list={zones.length > 0 ? 'site-edit-timezones' : undefined}
              maxLength={TIMEZONE_MAX}
              error={errors.timezone}
              className="font-mono"
              onChange={(e) => setTimezone(e.target.value)}
            />
            {zones.length > 0 && (
              <datalist id="site-edit-timezones">
                {zones.map((z) => <option key={z} value={z} />)}
              </datalist>
            )}
          </div>
          <div className="flex flex-wrap gap-1.5">
            {names.map((label, day) => (
              <button
                key={day}
                type="button"
                onClick={() => toggleDay(day)}
                aria-pressed={days.includes(day)}
                className={cn(
                  'rounded-md border px-2 py-1 text-[12px] transition-colors disabled:cursor-not-allowed disabled:opacity-50',
                  days.includes(day)
                    ? 'border-accent bg-accent/10 text-accent'
                    : 'border-border bg-bg-tertiary text-text-muted hover:text-text-primary',
                )}
              >
                {label}
              </button>
            ))}
          </div>
          <div className="grid grid-cols-2 gap-3">
            <Input
              id="site-edit-window-start"
              label={t('sites.fields.windowStart')}
              type="time"
              value={start}
              onChange={(e) => setStart(e.target.value)}
            />
            <Input
              id="site-edit-window-end"
              label={t('sites.fields.windowEnd')}
              type="time"
              value={end}
              onChange={(e) => setEnd(e.target.value)}
            />
          </div>
          {errors.window && <p className="text-xs text-status-down">{errors.window}</p>}
          {canSchedule && (days.length > 0 || start || end) && (
            <Button type="button" variant="ghost" size="sm" onClick={() => { setDays([]); setStart(''); setEnd(''); }}>
              {t('sites.edit.clearWindow', { defaultValue: 'No window' })}
            </Button>
          )}
        </fieldset>

        <div className="flex justify-end gap-2">
          <Button type="button" variant="secondary" size="sm" onClick={onCancel}>
            {t('common.cancel')}
          </Button>
          <Button type="submit" size="sm" loading={saving}>
            {t('common.save')}
          </Button>
        </div>
      </form>
    </section>
  );
}

// ============================================================================
// The delete dialog — shared by the site page and the Sites list
// ============================================================================

export interface SiteDeleteReport extends SiteDeleteImpact {
  siteId: number;
  code: string;
  name: string;
}

/**
 * Says what a delete removes and what it leaves behind, read from the server
 * (`deletion` of the edit context), and asks one explicit "I know" per thing
 * that stays outside ObliWAN's hold or is lost: the L2TP account that is, or
 * may be, on the concentrator (never removed by ObliWAN), the bench history
 * (kept, detached) and the SLA reports (deleted with the site). The DELETE
 * names exactly those acknowledgements, so something that appeared after the
 * dialog opened is refused by the server instead of being covered.
 */
export function SiteDeleteDialog({
  site,
  onClose,
  onDeleted,
}: {
  site: { id: number; code: string; name: string };
  onClose: () => void;
  onDeleted: (report: SiteDeleteReport | null) => void;
}) {
  const { t } = useTranslation();
  const [loading, setLoading] = useState(true);
  const [impact, setImpact] = useState<SiteDeleteImpact | null>(null);
  const [acknowledged, setAcknowledged] = useState<SiteDeleteAcknowledgement[]>([]);
  const [deleting, setDeleting] = useState(false);
  const [refusal, setRefusal] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    const ctx = await fetchSiteEditContext(site.id);
    setImpact(ctx?.deletion ?? null);
    setAcknowledged([]);
    setLoading(false);
  }, [site.id]);

  useEffect(() => {
    void load();
  }, [load]);

  const required = impact?.acknowledge ?? [];
  const ready = !loading && required.every((a) => acknowledged.includes(a));

  const toggle = (a: SiteDeleteAcknowledgement) =>
    setAcknowledged((prev) => (prev.includes(a) ? prev.filter((x) => x !== a) : [...prev, a]));

  const confirmDelete = async () => {
    setDeleting(true);
    setRefusal(null);
    try {
      const res = await apiClient.delete<ApiResponse<unknown>>(`/sites/${site.id}`, {
        params: required.length > 0 ? { acknowledge: required.join(',') } : undefined,
      });
      const data = res.data.data as Record<string, unknown> | undefined;
      const reportImpact = normalizeImpact(data);
      const report: SiteDeleteReport | null = reportImpact
        ? { ...reportImpact, siteId: site.id, code: site.code, name: site.name }
        : null;
      const kept = report?.chrAccountKept ?? impact?.chrAccountKept ?? null;
      toast.success(
        kept
          ? chrAccountUncertain(kept)
            ? t('sites.deleteDialog.deletedAccountPossible', {
                login: kept.pppUsername,
                defaultValue: 'Site deleted. The L2TP account {{login}} may be on the concentrator: check it there.',
              })
            : t('sites.deleteDialog.deletedAccountKept', {
                login: kept.pppUsername,
                defaultValue: 'Site deleted. The L2TP account {{login}} stays on the concentrator.',
              })
          : t('sites.deleted'),
      );
      onDeleted(report);
    } catch (err) {
      const { status, message } = errorOf(err);
      setRefusal(message ?? t('sites.failedDelete'));
      // A 409 means what is there changed since the dialog read it: read again.
      if (status === 409) await load();
    } finally {
      setDeleting(false);
    }
  };

  const titleId = `site-delete-title-${site.id}`;
  const allocation = impact?.allocationReleased ?? null;

  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center overflow-y-auto bg-black/60 p-4">
      <div
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        className="my-16 w-full max-w-lg rounded-xl border border-border bg-bg-secondary shadow-2xl"
      >
        <div className="flex items-center gap-2 border-b border-border px-5 py-4">
          <Trash2 size={18} className="text-status-down" />
          <h2 id={titleId} className="flex-1 text-base font-semibold text-text-primary">
            {t('sites.deleteDialog.title', {
              code: site.code,
              name: site.name,
              defaultValue: 'Delete site {{code}} ({{name}})?',
            })}
          </h2>
          <button
            type="button"
            onClick={onClose}
            className="rounded p-1 text-text-muted hover:text-text-primary"
            aria-label={t('common.close')}
          >
            <X size={16} />
          </button>
        </div>

        <div className="space-y-3 p-5 text-sm text-text-secondary">
          {loading ? (
            <div className="flex justify-center py-4"><LoadingSpinner /></div>
          ) : impact === null ? (
            <p>
              {t('sites.deleteDialog.unavailable', {
                defaultValue:
                  'What this delete would leave behind could not be read. If an account on the concentrator, bench history or SLA reports are involved, the server refuses and says so.',
              })}
            </p>
          ) : (
            <ul className="list-disc space-y-1.5 pl-5">
              <li>{t('sites.deleteDialog.variables', { defaultValue: 'Its site variables are deleted.' })}</li>
              <li>
                {t('sites.deleteDialog.devices', {
                  count: impact.devicesDetached,
                  defaultValue: '{{count}} device(s) stay, detached from the site.',
                })}
              </li>
              {allocation && (
                <li>
                  {t('sites.deleteDialog.allocation', {
                    login: allocation.pppUsername,
                    tunnel: allocation.tunnelIp,
                    defaultValue: 'Its address allocation (login {{login}}, tunnel address {{tunnel}}) is no longer held by ObliWAN.',
                  })}
                </li>
              )}
              {impact.chrAccountKept && (
                <li className="text-status-pending">
                  {chrAccountUncertain(impact.chrAccountKept)
                    ? t('sites.deleteDialog.chrAccountPossible', {
                        login: impact.chrAccountKept.pppUsername,
                        tunnel: impact.chrAccountKept.tunnelIp,
                        defaultValue:
                          'The L2TP account {{login}} (tunnel address {{tunnel}}) may be on the concentrator: a job may be creating it right now, or an earlier job created or found it, or lost the answer to its creation. If it is there it stays: ObliWAN never removes it. Check the concentrator by hand.',
                      })
                    : t('sites.deleteDialog.chrAccount', {
                        login: impact.chrAccountKept.pppUsername,
                        tunnel: impact.chrAccountKept.tunnelIp,
                        defaultValue:
                          'The L2TP account {{login}} (tunnel address {{tunnel}}) stays on the concentrator: ObliWAN never removes it. Remove it there by hand if it is no longer needed.',
                      })}
                </li>
              )}
              {impact.benchHistoryKept > 0 && (
                <li className="text-status-pending">
                  {t('sites.deleteDialog.benchHistory', {
                    count: impact.benchHistoryKept,
                    defaultValue:
                      '{{count}} bench preparation record(s) are kept as history, detached from the site, with its code and name.',
                  })}
                </li>
              )}
              {impact.slaReportsDeleted > 0 && (
                <li className="text-status-down">
                  {t('sites.deleteDialog.slaReports', {
                    count: impact.slaReportsDeleted,
                    defaultValue: '{{count}} SLA report(s) of the site are deleted with it and can no longer be consulted.',
                  })}
                </li>
              )}
              {impact.slaObjectivesDeleted > 0 && (
                <li>
                  {t('sites.deleteDialog.slaObjectives', {
                    count: impact.slaObjectivesDeleted,
                    defaultValue: 'Its {{count}} site SLA objective(s) are deleted.',
                  })}
                </li>
              )}
            </ul>
          )}

          {!loading && required.length > 0 && (
            <div className="space-y-2 rounded-md border border-status-pending/40 bg-status-pending/10 p-3">
              {required.includes('chr_account') && (
                <label className="flex items-start gap-2 text-text-primary">
                  <input
                    type="checkbox"
                    className="mt-0.5"
                    checked={acknowledged.includes('chr_account')}
                    onChange={() => toggle('chr_account')}
                  />
                  <span>
                    {chrAccountUncertain(impact?.chrAccountKept)
                      ? t('sites.deleteDialog.acknowledgeChrPossible', {
                          login: impact?.chrAccountKept?.pppUsername ?? '—',
                          defaultValue: 'I know the L2TP account {{login}} may stay on the concentrator.',
                        })
                      : t('sites.deleteDialog.acknowledgeChr', {
                          login: impact?.chrAccountKept?.pppUsername ?? '—',
                          defaultValue: 'I know the L2TP account {{login}} stays on the concentrator.',
                        })}
                  </span>
                </label>
              )}
              {required.includes('bench_history') && (
                <label className="flex items-start gap-2 text-text-primary">
                  <input
                    type="checkbox"
                    className="mt-0.5"
                    checked={acknowledged.includes('bench_history')}
                    onChange={() => toggle('bench_history')}
                  />
                  <span>
                    {t('sites.deleteDialog.acknowledgeBench', {
                      defaultValue: 'I know the bench history is kept without its site.',
                    })}
                  </span>
                </label>
              )}
              {required.includes('sla_history') && (
                <label className="flex items-start gap-2 text-text-primary">
                  <input
                    type="checkbox"
                    className="mt-0.5"
                    checked={acknowledged.includes('sla_history')}
                    onChange={() => toggle('sla_history')}
                  />
                  <span>
                    {t('sites.deleteDialog.acknowledgeSla', {
                      defaultValue: 'I know the site’s SLA reports are deleted with it.',
                    })}
                  </span>
                </label>
              )}
            </div>
          )}

          {refusal && (
            <p role="alert" className="rounded-md border border-status-down/40 bg-status-down/10 px-3 py-2 text-status-down">
              {refusal}
            </p>
          )}
        </div>

        <div className="flex justify-end gap-2 border-t border-border px-5 py-3">
          <Button type="button" variant="secondary" size="sm" onClick={onClose}>
            {t('common.cancel')}
          </Button>
          <Button type="button" variant="danger" size="sm" disabled={!ready} loading={deleting} onClick={() => void confirmDelete()}>
            {t('common.delete')}
          </Button>
        </div>
      </div>
    </div>
  );
}
