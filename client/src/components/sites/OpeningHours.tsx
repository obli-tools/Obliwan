import { useEffect, useMemo, useState, type ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import toast from 'react-hot-toast';
import { Clock, Store, X } from 'lucide-react';
import {
  CAPABILITIES,
  OPENING_DAYS,
  formatOpeningHours,
  parseOpeningHoursText,
  type OpeningHours,
  type SiteOpenState,
} from '@obliwan/shared';
import { Button } from '@/components/common/Button';
import { cn } from '@/utils/cn';
import { sitesApi } from '@/api/sites.api';
import { useSiteStore } from '@/store/siteStore';
import { useAuthStore } from '@/store/authStore';
import { apiErrorText, openingHoursApi, type OpeningHoursBulkMode } from '@/api/openingHours.api';
import type { Site } from '@/types/fleet';

/**
 * Store opening hours (migration 096) on screen: « Ouvert / Fermé maintenant »,
 * the readable text editor with its preview, the workspace's hours, a site's
 * own hours and the bulk write on selected sites.
 *
 * The open state is always the SERVER's, computed in the site's own time zone;
 * the client only parses and previews what the operator types, with the same
 * shared parser the server applies.
 */

/** What the site endpoints add to a site (list: openState; detail: all). */
export interface SiteOpeningFields {
  openingHours?: OpeningHours | null;
  openState?: SiteOpenState;
  tenantOpeningHours?: OpeningHours | null;
  maintenanceFromClosedHours?: boolean;
}

function langOf(language: string): 'fr' | 'en' {
  return language.startsWith('fr') ? 'fr' : 'en';
}

function formatInstant(iso: string, language: string, timeZone?: string): string {
  try {
    return new Intl.DateTimeFormat(language, {
      weekday: 'short',
      hour: '2-digit',
      minute: '2-digit',
      ...(timeZone ? { timeZone } : {}),
    }).format(new Date(iso));
  } catch {
    return new Date(iso).toLocaleString();
  }
}

/** « Ouvert » / « Fermé » now; nothing (a dash when `dash`) when no hours are known. */
export function OpenStateBadge({
  state,
  timezone,
  dash = false,
  className,
}: {
  state: SiteOpenState | undefined | null;
  timezone?: string;
  dash?: boolean;
  className?: string;
}) {
  const { t, i18n } = useTranslation();
  if (!state || state.open === null) {
    return dash ? <span className="text-text-muted" title={t('openingHours.unknownHint')}>—</span> : null;
  }
  const next = state.nextChangeAt ? formatInstant(state.nextChangeAt, i18n.language, timezone) : null;
  const title = state.open
    ? next ? t('openingHours.closesAt', { when: next }) : t('openingHours.openNow')
    : next ? t('openingHours.opensAt', { when: next }) : t('openingHours.closedNow');
  return (
    <span
      className={cn(
        'inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-[10px] font-medium',
        state.open
          ? 'border-status-up/40 bg-status-up/10 text-status-up'
          : 'border-border bg-bg-tertiary text-text-muted',
        className,
      )}
      title={title}
    >
      <Store size={10} />
      {state.open ? t('openingHours.open') : t('openingHours.closed')}
    </span>
  );
}

/** The device page: the open state of the device's site (from the list, else fetched once). */
export function SiteOpenStateInline({ siteId }: { siteId: number | null }) {
  const listed = useSiteStore((s) => s.sites.find((x) => x.id === siteId)) as (Site & SiteOpeningFields) | undefined;
  const [fetched, setFetched] = useState<(Site & SiteOpeningFields) | null>(null);
  useEffect(() => {
    if (siteId === null || listed?.openState) return;
    let gone = false;
    sitesApi
      .getById(siteId)
      .then((s) => { if (!gone) setFetched(s as Site & SiteOpeningFields); })
      .catch(() => undefined);
    return () => { gone = true; };
  }, [siteId, listed?.openState]);
  const site = listed?.openState ? listed : fetched;
  if (!site) return null;
  return <OpenStateBadge state={site.openState} timezone={site.timezone} />;
}

/** One line per day (and the exceptions), as the server will read the text. */
function HoursPreview({ hours }: { hours: OpeningHours }) {
  const { t } = useTranslation();
  return (
    <div className="mt-2 grid grid-cols-1 gap-x-6 gap-y-0.5 text-[11px] text-text-secondary sm:grid-cols-2">
      {hours.week === null ? (
        <p className="italic text-text-muted">{t('openingHours.noWeek')}</p>
      ) : (
        OPENING_DAYS.map((d) => (
          <div key={d} className="flex gap-2">
            <span className="w-20 text-text-muted">{t(`openingHours.days.${d}`)}</span>
            <span className="font-mono">
              {hours.week![d].length === 0
                ? t('openingHours.closed')
                : hours.week![d].map((r) => `${r.open}–${r.close}`).join(', ')}
            </span>
          </div>
        ))
      )}
      {hours.exceptions.map((e) => (
        <div key={e.date} className="flex gap-2">
          <span className="w-20 font-mono text-text-muted">{e.date}</span>
          <span className="font-mono">
            {e.ranges.length === 0 ? t('openingHours.closed') : e.ranges.map((r) => `${r.open}–${r.close}`).join(', ')}
          </span>
        </div>
      ))}
    </div>
  );
}

/** The readable text, parsed as it is typed. `parsed` is null while it does not read. */
export function OpeningHoursText({
  text,
  onChange,
  disabled,
}: {
  text: string;
  onChange: (text: string, parsed: OpeningHours | null) => void;
  disabled?: boolean;
}) {
  const { t } = useTranslation();
  const result = useMemo(() => (text.trim() === '' ? null : parseOpeningHoursText(text)), [text]);
  return (
    <div>
      <textarea
        value={text}
        onChange={(e) => {
          const r = e.target.value.trim() === '' ? null : parseOpeningHoursText(e.target.value);
          onChange(e.target.value, r && r.ok ? r.value : null);
        }}
        disabled={disabled}
        rows={3}
        spellCheck={false}
        placeholder={t('openingHours.placeholder')}
        className="w-full rounded-md border border-border bg-bg-tertiary px-3 py-2 font-mono text-[12px] text-text-primary focus:outline-none focus:ring-2 focus:ring-accent"
      />
      <p className="mt-1 text-[11px] text-text-muted">{t('openingHours.formatHint')}</p>
      {result && !result.ok && <p className="mt-1 text-[11px] text-status-down">{result.error}</p>}
      {result && result.ok && <HoursPreview hours={result.value} />}
    </div>
  );
}

function Dialog({ title, onClose, children }: { title: string; onClose: () => void; children: ReactNode }) {
  const { t } = useTranslation();
  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center overflow-y-auto bg-black/60 p-4">
      <div className="my-8 w-full max-w-2xl rounded-xl border border-border bg-bg-secondary shadow-2xl">
        <div className="flex items-center gap-2 border-b border-border px-5 py-4">
          <Clock size={18} className="text-accent" />
          <h2 className="flex-1 text-base font-semibold text-text-primary">{title}</h2>
          <button
            type="button"
            onClick={onClose}
            className="rounded p-1 text-text-muted hover:bg-bg-hover hover:text-text-primary"
            aria-label={t('common.close', { defaultValue: 'Close' })}
          >
            <X size={16} />
          </button>
        </div>
        <div className="space-y-4 px-5 py-4">{children}</div>
      </div>
    </div>
  );
}

/**
 * Who may edit the WORKSPACE's hours: SITE_WRITE and rw on every site (they
 * reach every site — the server's requireEverySiteWritable, like a create).
 */
export function useCanEditTenantHours(): boolean {
  const { hasCapability, canCreateSites } = useAuthStore();
  return (hasCapability(CAPABILITIES.SITE_WRITE) || hasCapability(CAPABILITIES.DEVICE_WRITE)) && canCreateSites();
}

/** The workspace's usual hours: every site without a week of its own inherits them. */
export function TenantOpeningHoursDialog({ canEdit, onClose, onSaved }: { canEdit: boolean; onClose: () => void; onSaved?: () => void }) {
  const { t, i18n } = useTranslation();
  const [text, setText] = useState('');
  const [parsed, setParsed] = useState<OpeningHours | null>(null);
  const [loaded, setLoaded] = useState(false);
  const [busy, setBusy] = useState(false);
  useEffect(() => {
    openingHoursApi
      .getTenant()
      .then((h) => {
        if (h) {
          const s = formatOpeningHours(h, langOf(i18n.language));
          setText(s);
          setParsed(h);
        }
      })
      .catch((err: unknown) => toast.error(apiErrorText(err) ?? t('openingHours.loadFailed')))
      .finally(() => setLoaded(true));
  }, [i18n.language, t]);
  const save = async (value: OpeningHours | null) => {
    setBusy(true);
    try {
      await openingHoursApi.putTenant(value);
      toast.success(value ? t('openingHours.tenantSaved') : t('openingHours.tenantCleared'));
      onSaved?.();
      onClose();
    } catch (err) {
      toast.error(apiErrorText(err) ?? t('openingHours.saveFailed'));
    } finally {
      setBusy(false);
    }
  };
  return (
    <Dialog title={t('openingHours.tenantTitle')} onClose={onClose}>
      <p className="text-xs text-text-muted">{t('openingHours.tenantHint')}</p>
      {!loaded ? null : (
        <OpeningHoursText text={text} disabled={!canEdit || busy} onChange={(s, p) => { setText(s); setParsed(p); }} />
      )}
      <EffectsNote />
      {canEdit && (
        <div className="flex justify-end gap-2">
          <Button variant="ghost" size="sm" onClick={() => void save(null)} disabled={busy}>
            {t('openingHours.clearTenant')}
          </Button>
          <Button size="sm" onClick={() => void save(parsed)} loading={busy} disabled={parsed === null}>
            {t('common.save', { defaultValue: 'Save' })}
          </Button>
        </div>
      )}
    </Dialog>
  );
}

/** What the hours change, said once wherever they are edited. */
function EffectsNote() {
  const { t } = useTranslation();
  return (
    <ul className="list-disc space-y-0.5 pl-5 text-[11px] text-text-muted">
      <li>{t('openingHours.effects.alerts')}</li>
      <li>{t('openingHours.effects.notify')}</li>
      <li>{t('openingHours.effects.maintenance')}</li>
      <li>{t('openingHours.effects.unknown')}</li>
    </ul>
  );
}

/** One write for the selected sites: replace, add dated exceptions, or back to the workspace's hours. */
export function OpeningHoursBulkDialog({ siteIds, onClose, onDone }: { siteIds: number[]; onClose: () => void; onDone: () => void }) {
  const { t } = useTranslation();
  const [ids] = useState(() => [...siteIds]);
  const [mode, setMode] = useState<OpeningHoursBulkMode | 'inherit'>('replace');
  const [text, setText] = useState('');
  const [parsed, setParsed] = useState<OpeningHours | null>(null);
  const [busy, setBusy] = useState(false);
  const apply = async () => {
    setBusy(true);
    try {
      const r = mode === 'inherit'
        ? await openingHoursApi.bulk(ids, null, 'replace')
        : await openingHoursApi.bulk(ids, parsed, mode);
      toast.success(t('openingHours.bulk.done', { changed: r.changed, unchanged: r.unchanged }));
      onDone();
      onClose();
    } catch (err) {
      toast.error(apiErrorText(err) ?? t('openingHours.bulk.failed'));
    } finally {
      setBusy(false);
    }
  };
  return (
    <Dialog title={t('openingHours.bulk.title', { count: ids.length })} onClose={onClose}>
      <div className="space-y-1 text-sm text-text-primary">
        {(['replace', 'merge', 'inherit'] as const).map((m) => (
          <label key={m} className="flex cursor-pointer items-start gap-2">
            <input type="radio" name="oh-mode" checked={mode === m} onChange={() => setMode(m)} className="mt-1 accent-accent" />
            <span>
              {t(`openingHours.bulk.mode.${m}`)}
              <span className="block text-[11px] text-text-muted">{t(`openingHours.bulk.modeHint.${m}`)}</span>
            </span>
          </label>
        ))}
      </div>
      {mode !== 'inherit' && (
        <OpeningHoursText text={text} disabled={busy} onChange={(s, p) => { setText(s); setParsed(p); }} />
      )}
      <div className="flex justify-end gap-2">
        <Button variant="ghost" size="sm" onClick={onClose} disabled={busy}>
          {t('common.cancel', { defaultValue: 'Cancel' })}
        </Button>
        <Button size="sm" onClick={() => void apply()} loading={busy} disabled={mode !== 'inherit' && parsed === null}>
          {t('openingHours.bulk.apply', { count: ids.length })}
        </Button>
      </div>
    </Dialog>
  );
}

/** The site page: its hours (own or inherited), open now, and the maintenance consequence. */
export function SiteOpeningHoursCard({
  site,
  canEdit,
  onSaved,
}: {
  site: Site & SiteOpeningFields;
  canEdit: boolean;
  onSaved: () => void;
}) {
  const { t, i18n } = useTranslation();
  const lang = langOf(i18n.language);
  const own = site.openingHours ?? null;
  const [editing, setEditing] = useState(false);
  const [text, setText] = useState('');
  const [parsed, setParsed] = useState<OpeningHours | null>(null);
  const [busy, setBusy] = useState(false);
  const [showTenant, setShowTenant] = useState(false);
  const startEdit = () => {
    setText(own ? formatOpeningHours(own, lang) : '');
    setParsed(own);
    setEditing(true);
  };
  const save = async (value: OpeningHours | null) => {
    setBusy(true);
    try {
      await openingHoursApi.setSite(site.id, value);
      toast.success(value ? t('openingHours.siteSaved') : t('openingHours.siteInherits'));
      setEditing(false);
      onSaved();
    } catch (err) {
      toast.error(apiErrorText(err) ?? t('openingHours.saveFailed'));
    } finally {
      setBusy(false);
    }
  };
  const inherited = site.tenantOpeningHours ?? null;
  const canEditTenant = useCanEditTenantHours();
  return (
    <section className="rounded-lg border border-border bg-bg-secondary p-4">
      <h2 className="mb-3 flex items-center gap-2 text-sm font-semibold uppercase tracking-wide text-text-secondary">
        <Clock size={14} />
        <span className="flex-1">{t('openingHours.sectionTitle')}</span>
        <OpenStateBadge state={site.openState} timezone={site.timezone} />
      </h2>
      {site.openState && site.openState.open === null && (
        <p className="mb-2 text-xs italic text-text-muted">{t('openingHours.unknownHint')}</p>
      )}
      <div className="space-y-2 text-[12px]">
        <div>
          <span className="text-text-muted">{t('openingHours.ownLabel')} </span>
          {own ? (
            <span className="font-mono text-text-primary">{formatOpeningHours(own, lang)}</span>
          ) : (
            <span className="italic text-text-muted">{t('openingHours.inheritsAll')}</span>
          )}
        </div>
        <div>
          <span className="text-text-muted">{t('openingHours.tenantLabel')} </span>
          {inherited ? (
            <span className="font-mono text-text-secondary">{formatOpeningHours(inherited, lang)}</span>
          ) : (
            <span className="italic text-text-muted">{t('openingHours.tenantNone')}</span>
          )}
          <button type="button" onClick={() => setShowTenant(true)} className="ml-2 text-accent hover:underline">
            {canEditTenant ? t('openingHours.editTenant') : t('openingHours.viewTenant')}
          </button>
        </div>
        {site.openState?.source && (
          <p className="text-[11px] text-text-muted">
            {site.openState.source === 'site' ? t('openingHours.weekFromSite') : t('openingHours.weekFromTenant')}
            {' · '}{t('sites.fields.timezone')}: <span className="font-mono">{site.timezone}</span>
          </p>
        )}
        {site.maintenanceFromClosedHours && (
          <p className="rounded-md border border-accent/30 bg-accent/5 px-2 py-1 text-[11px] text-text-secondary">
            {t('openingHours.maintenanceFromClosedHours')}
          </p>
        )}
      </div>
      {editing ? (
        <div className="mt-3 space-y-2">
          <OpeningHoursText text={text} disabled={busy} onChange={(s, p) => { setText(s); setParsed(p); }} />
          <div className="flex flex-wrap justify-end gap-2">
            <Button variant="ghost" size="sm" onClick={() => setEditing(false)} disabled={busy}>
              {t('common.cancel', { defaultValue: 'Cancel' })}
            </Button>
            <Button variant="secondary" size="sm" onClick={() => void save(null)} disabled={busy}>
              {t('openingHours.inheritButton')}
            </Button>
            <Button size="sm" onClick={() => void save(parsed)} loading={busy} disabled={parsed === null}>
              {t('common.save', { defaultValue: 'Save' })}
            </Button>
          </div>
        </div>
      ) : (
        canEdit && (
          <div className="mt-3">
            <Button variant="secondary" size="sm" onClick={startEdit}>
              {t('openingHours.editSite')}
            </Button>
          </div>
        )
      )}
      {showTenant && <TenantOpeningHoursDialog canEdit={canEditTenant} onClose={() => setShowTenant(false)} onSaved={onSaved} />}
    </section>
  );
}
