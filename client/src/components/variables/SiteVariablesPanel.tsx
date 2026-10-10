import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import toast from 'react-hot-toast';
import { KeyRound, Lock, RotateCcw, Search, Undo2 } from 'lucide-react';
import { sitesApi } from '@/api/sites.api';
import {
  variablesApi,
  type DeclaredSiteKey,
  type JsonValue,
  type SiteVariableForm,
  type StoredVariable,
} from '@/api/variables.api';
import type { Site } from '@/types/fleet';
import { Button } from '@/components/common/Button';
import { LoadingSpinner } from '@/components/common/LoadingSpinner';
import { cn } from '@/utils/cn';
import { apiErrorText, displayValue, parseDraft, parseFailureText, type ValueKind } from './valueKinds';

/**
 * The SITE form: one field per key the published templates declare, generated
 * from each key's JSON Schema and labelled with its `x-obliwan-label`.
 *
 * What the server decides, and this screen only reflects:
 *  - whether a key may be typed here at all (`siteWritable`: every declaring
 *    revision says `x-obliwan-level: 'site'`), and whether the declarations
 *    agree on secrecy (`secrecyConflict`);
 *  - whether a value goes to the vault — the DECLARATION decides, so the save
 *    body has no `isSecret`;
 *  - whether a value is valid: the PUT is all or nothing and a refusal (422)
 *    lists every refused key, which is drawn under its own field.
 *
 * A secret is write-only here: the field shows "set" / "not set" and an empty
 * input that replaces it; nothing in this panel shows its value. The one way
 * to SEE it is the optional `secretReveal` slot, which the page fills with a
 * `RevealSecretButton` (SECRET_READ): that button fetches the plaintext on
 * click and holds it for 30 seconds in its own state, never in this panel's.
 */

type FieldKind = ValueKind | 'enum';

interface FieldSpec {
  kind: FieldKind;
  integer: boolean;
  options: JsonValue[];
  placeholder?: string;
  description?: string;
  defaultValue?: JsonValue;
}

function fieldSpec(d: DeclaredSiteKey): FieldSpec {
  const s = d.schema ?? {};
  const type = Array.isArray(s.type) ? s.type.find((x) => x !== 'null') : s.type;
  const description = typeof s.description === 'string' ? s.description : undefined;
  const defaultValue = 'default' in s ? (s.default as JsonValue) : undefined;
  const examples = Array.isArray(s.examples) ? s.examples : [];
  const placeholder =
    examples.length > 0 && (typeof examples[0] === 'string' || typeof examples[0] === 'number')
      ? String(examples[0])
      : typeof s.format === 'string' ? s.format : undefined;
  const base = { integer: type === 'integer', options: [] as JsonValue[], placeholder, description, defaultValue };

  if (d.secret) return { ...base, kind: 'secret' };
  if (Array.isArray(s.enum) && s.enum.length > 0) return { ...base, kind: 'enum', options: s.enum as JsonValue[] };
  if (type === 'boolean') return { ...base, kind: 'boolean' };
  if (type === 'integer' || type === 'number') return { ...base, kind: 'number' };
  if (type === 'string') return { ...base, kind: 'text' };
  return { ...base, kind: 'json' };
}

/** The text a field starts from: the value set at the site, else empty. */
function initialDraft(spec: FieldSpec, current: StoredVariable | undefined): string {
  if (!current || current.isSecret || spec.kind === 'secret') return '';
  const v = current.value;
  switch (spec.kind) {
    case 'enum': return JSON.stringify(v);
    case 'boolean': return v === true ? 'true' : v === false ? 'false' : '';
    case 'number': return typeof v === 'number' ? String(v) : '';
    case 'text': return typeof v === 'string' ? v : displayValue(v);
    default: return JSON.stringify(v, null, 2);
  }
}

export function SiteVariablesPanel({
  siteId,
  onSiteChange,
  onDirtyChange,
  canWrite,
  reloadKey,
  secretReveal,
}: {
  siteId: number | null;
  onSiteChange: (id: number | null) => void;
  /** Told whether unsaved changes exist, so the page can ask before a tab change. */
  onDirtyChange?: (dirty: boolean) => void;
  canWrite: boolean;
  reloadKey?: unknown;
  /** Drawn next to a secret set AT this site: the page's reveal control for it.
   *  `siteId` is the site of the form on screen; `fingerprint` the value's
   *  keyed fingerprint, which changes when the secret is replaced — a revealed
   *  value must not outlive it. Omitted, no reveal control. */
  secretReveal?: (siteId: number, key: string, fingerprint: unknown) => ReactNode;
}) {
  const { t } = useTranslation();

  // ── Site picker ───────────────────────────────────────────────────────────
  const [search, setSearch] = useState('');
  const [sites, setSites] = useState<Site[]>([]);
  const [sitesLoading, setSitesLoading] = useState(false);

  useEffect(() => {
    let alive = true;
    const handle = window.setTimeout(() => {
      setSitesLoading(true);
      sitesApi.list(search.trim() ? { search: search.trim() } : {})
        .then((list) => { if (alive) setSites(list); })
        .catch(() => { if (alive) setSites([]); })
        .finally(() => { if (alive) setSitesLoading(false); });
    }, 250);
    return () => { alive = false; window.clearTimeout(handle); };
  }, [search, reloadKey]);

  // ── The form ──────────────────────────────────────────────────────────────
  const [form, setForm] = useState<SiteVariableForm | null>(null);
  const [loading, setLoading] = useState(false);
  const [loadError, setLoadError] = useState<string | null>(null);
  /** Text typed per key; a key is absent until its field is touched. */
  const [drafts, setDrafts] = useState<Record<string, string>>({});
  /** Keys to remove at the site, so the site inherits again. */
  const [unset, setUnset] = useState<Set<string>>(new Set());
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [banner, setBanner] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);

  const reset = () => { setDrafts({}); setUnset(new Set()); setErrors({}); setBanner(null); };

  /** The site whose form was asked for LAST. A slower answer for a site the
   *  user has since left is dropped: drawn under the newer site's id, its
   *  values would be edited and saved into the wrong site. */
  const requestedSite = useRef<number | null>(null);
  /** Unsaved changes exist (kept in a ref so the reset effect sees the value
   *  from before the reset). */
  const dirtyRef = useRef(false);

  const loadForm = useCallback(async (id: number) => {
    requestedSite.current = id;
    setLoading(true);
    try {
      const next = await variablesApi.siteForm(id);
      if (requestedSite.current !== id) return;
      setForm(next);
      setLoadError(null);
    } catch (err) {
      if (requestedSite.current !== id) return;
      setForm(null);
      setLoadError(apiErrorText(err) ?? t('variables.site.loadFailed', {
        defaultValue: 'Could not load this site\'s values.',
      }));
    } finally {
      if (requestedSite.current === id) setLoading(false);
    }
  }, [t]);

  useEffect(() => {
    // Reached with unsaved changes only when the site changed without the
    // picker (browser back, a link) or the tenant changed: the drafts belong to
    // a site that is no longer on screen and must not follow the user.
    if (dirtyRef.current) {
      dirtyRef.current = false;
      toast(t('variables.site.discarded', { defaultValue: 'Unsaved changes for the previous site were discarded.' }));
    }
    reset();
    setForm(null);
    if (siteId === null) { requestedSite.current = null; setLoading(false); return; }
    void loadForm(siteId);
  }, [siteId, loadForm, reloadKey]);

  const specs = useMemo(
    () => new Map((form?.declared ?? []).map((d) => [d.key, fieldSpec(d)])),
    [form],
  );

  const isDirty = (d: DeclaredSiteKey): boolean => {
    if (unset.has(d.key)) return true;
    const draft = drafts[d.key];
    if (draft === undefined) return false;
    const spec = specs.get(d.key)!;
    if (spec.kind === 'secret') return draft.length > 0;
    return draft !== initialDraft(spec, form?.values[d.key]);
  };

  const declared = form?.declared ?? [];
  const dirtyCount = declared.filter(isDirty).length;

  useEffect(() => {
    dirtyRef.current = dirtyCount > 0;
    onDirtyChange?.(dirtyCount > 0);
    if (dirtyCount === 0) return undefined;
    // Closing or reloading the browser tab with typed values asks first.
    const guard = (e: BeforeUnloadEvent) => { e.preventDefault(); e.returnValue = ''; };
    window.addEventListener('beforeunload', guard);
    return () => window.removeEventListener('beforeunload', guard);
  }, [dirtyCount, onDirtyChange]);

  const changeSite = (id: number | null) => {
    if (dirtyCount > 0 && !window.confirm(t('variables.site.discardConfirm', {
      defaultValue: 'This site has unsaved changes. Leave and lose them?',
    }))) return;
    dirtyRef.current = false; // confirmed: no second notice from the reset effect
    onSiteChange(id);
  };

  /** Groups the form: what can be typed for a site first, and the keys that are
   *  never typed here (computed, bench, per-router, wider levels) folded away. */
  const lockedHere = (d: DeclaredSiteKey) => !d.siteWritable && !d.secrecyConflict;
  const entryKeys = declared.filter((d) => !lockedHere(d));
  const lockedKeys = declared.filter(lockedHere);
  const undeclared = form
    ? Object.values(form.values).filter((v) => !specs.has(v.key)).sort((a, b) => a.key.localeCompare(b.key))
    : [];

  const save = async () => {
    // The baseline the user edited must be the site being written to.
    if (!form || siteId === null || form.site.id !== siteId) return;
    const entries: { key: string; value: JsonValue }[] = [];
    const localErrors: Record<string, string> = {};
    for (const d of declared) {
      if (!isDirty(d) || unset.has(d.key)) continue;
      const spec = specs.get(d.key)!;
      const text = drafts[d.key] ?? '';
      if (spec.kind === 'enum') {
        if (text === '') { localErrors[d.key] = parseFailureText(t, 'empty'); continue; }
        entries.push({ key: d.key, value: JSON.parse(text) as JsonValue });
        continue;
      }
      const parsed = parseDraft(text, spec.kind, { integer: spec.integer });
      if (!parsed.ok) { localErrors[d.key] = parseFailureText(t, parsed.reason); continue; }
      entries.push({ key: d.key, value: parsed.value });
    }
    setErrors(localErrors);
    if (Object.keys(localErrors).length > 0) {
      setBanner(t('variables.site.fixErrors', { defaultValue: 'Some values need correcting. Nothing was saved.' }));
      return;
    }
    if (entries.length === 0 && unset.size === 0) return;

    setSaving(true);
    setBanner(null);
    try {
      const result = await variablesApi.saveSiteForm(siteId, { entries, unset: [...unset] });
      if (!result.ok) {
        const byKey: Record<string, string> = {};
        for (const e of result.errors) byKey[e.key] = e.message;
        setErrors(byKey);
        setBanner(t('variables.site.refused', {
          defaultValue: 'Nothing was saved: {{count}} value(s) were refused. Each reason is shown under its field.',
          count: result.errors.length,
        }));
        return;
      }
      toast.success(t('variables.site.saved', { defaultValue: 'Site values saved.' }));
      reset();
      await loadForm(siteId);
    } catch (err) {
      setBanner(apiErrorText(err) ?? t('variables.saveFailed', { defaultValue: 'Could not save.' }));
    } finally {
      setSaving(false);
    }
  };

  const inputCls = (bad: boolean) => cn(
    'w-full rounded-md border bg-bg-tertiary px-3 py-2 text-sm text-text-primary placeholder:text-text-muted',
    'focus:outline-none focus:ring-2 focus:ring-accent disabled:opacity-60',
    bad ? 'border-status-down' : 'border-border',
  );

  const renderInput = (d: DeclaredSiteKey, spec: FieldSpec, disabled: boolean): ReactNode => {
    const current = form?.values[d.key];
    const value = drafts[d.key] ?? initialDraft(spec, current);
    const bad = Boolean(errors[d.key]);
    const set = (text: string) => {
      setDrafts((prev) => ({ ...prev, [d.key]: text }));
      if (unset.has(d.key)) setUnset((prev) => { const n = new Set(prev); n.delete(d.key); return n; });
    };
    switch (spec.kind) {
      case 'enum':
        return (
          <select value={value} disabled={disabled} onChange={(e) => set(e.target.value)} className={inputCls(bad)}>
            <option value="">{t('variables.site.choose', { defaultValue: '— choose —' })}</option>
            {spec.options.map((o) => (
              <option key={JSON.stringify(o)} value={JSON.stringify(o)}>{displayValue(o)}</option>
            ))}
          </select>
        );
      case 'boolean':
        return (
          <select value={value} disabled={disabled} onChange={(e) => set(e.target.value)} className={inputCls(bad)}>
            <option value="">{t('variables.site.choose', { defaultValue: '— choose —' })}</option>
            <option value="true">{t('common.yes')}</option>
            <option value="false">{t('common.no')}</option>
          </select>
        );
      case 'json':
        return (
          <textarea
            value={value}
            disabled={disabled}
            rows={3}
            spellCheck={false}
            onChange={(e) => set(e.target.value)}
            className={cn(inputCls(bad), 'font-mono')}
          />
        );
      default:
        return (
          <input
            value={value}
            disabled={disabled}
            onChange={(e) => set(e.target.value)}
            type={spec.kind === 'secret' ? 'password' : 'text'}
            inputMode={spec.kind === 'number' ? (spec.integer ? 'numeric' : 'decimal') : undefined}
            autoComplete={spec.kind === 'secret' ? 'new-password' : 'off'}
            placeholder={spec.kind === 'secret'
              ? (current
                ? t('variables.secretReplacePlaceholder', { defaultValue: 'Type the new value to replace it' })
                : t('variables.site.secretNewPlaceholder', { defaultValue: 'Type the value' }))
              : spec.placeholder}
            className={inputCls(bad)}
          />
        );
    }
  };

  const withheldReason = (d: DeclaredSiteKey): string => {
    if (d.secrecyConflict) {
      return t('variables.site.secrecyConflict', {
        defaultValue: 'The templates disagree on whether this value is secret. The template author must settle it first.',
      });
    }
    // The first withholding declaration names the reason; the server's own
    // wording (describeWithheld in variableResolver.service.ts) branches the same way.
    const by = d.withheldBy[0];
    const template = by?.templateName ?? '—';
    switch (by?.level ?? null) {
      case 'computed':
        return t('variables.site.levelComputed', {
          defaultValue: 'Calculated by ObliWAN when the configuration is built (template "{{template}}"). Nobody types it.',
          template,
        });
      case 'bench':
        return t('variables.site.levelBench', {
          defaultValue: 'Typed at the preparation bench for each router (template "{{template}}"). It is never stored.',
          template,
        });
      case 'device':
        return t('variables.site.levelDevice', {
          defaultValue: 'Set router by router, not per site (template "{{template}}").',
          template,
        });
      case 'instance':
        return t('variables.site.levelInstance', {
          defaultValue: 'Set once for all clients, on the Instance tab (template "{{template}}").',
          template,
        });
      case 'global':
      case 'tenant':
      case 'group':
        return t('variables.site.notSiteLevel', {
          defaultValue: 'Not entered site by site: template "{{template}}" sets it for the whole client or group.',
          template,
        });
      default:
        return t('variables.site.levelNone', {
          defaultValue:
            'Template "{{template}}" does not say at which level this value is entered, so it cannot be set per site. '
            + 'The template author must state it.',
          template,
        });
    }
  };

  return (
    <div>
      <p className="mb-4 max-w-3xl text-sm text-text-secondary">
        {t('variables.site.hint', {
          defaultValue:
            'Values that belong to one site (its address range, its internet access, its passwords). They win over '
            + 'the client\'s values. The fields come from the templates in use.',
        })}
      </p>

      {/* Site picker */}
      <div className="mb-5 grid grid-cols-1 gap-3 md:grid-cols-2">
        <label className="relative block">
          <Search size={14} className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-text-muted" />
          <input
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder={t('variables.site.searchPlaceholder', { defaultValue: 'Search a site by name or number' })}
            className="w-full rounded-md border border-border bg-bg-tertiary py-2 pl-9 pr-3 text-sm text-text-primary placeholder:text-text-muted focus:outline-none focus:ring-2 focus:ring-accent"
          />
        </label>
        <select
          value={siteId ?? ''}
          onChange={(e) => changeSite(e.target.value === '' ? null : Number(e.target.value))}
          className="w-full rounded-md border border-border bg-bg-tertiary px-3 py-2 text-sm text-text-primary focus:outline-none focus:ring-2 focus:ring-accent"
        >
          <option value="">
            {sitesLoading
              ? t('common.loading')
              : t('variables.site.pick', { defaultValue: '— choose a site ({{count}}) —', count: sites.length })}
          </option>
          {siteId !== null && form && !sites.some((s) => s.id === siteId) && (
            <option value={siteId}>{form.site.code} — {form.site.name}</option>
          )}
          {/* God view: every tenant's sites, each named with its client (the
              form then opens in the site's own tenant, server-side). */}
          {sites.map((s) => (
            <option key={s.id} value={s.id}>
              {s.code} — {s.name}{s.tenantName ? ` · ${s.tenantName}` : ''}
            </option>
          ))}
        </select>
      </div>

      {siteId === null ? (
        <div className="rounded-lg border border-dashed border-border px-6 py-12 text-center text-sm text-text-secondary">
          {t('variables.site.noneSelected', { defaultValue: 'Choose a site to see and fill in its values.' })}
        </div>
      ) : loading ? <LoadingSpinner /> : loadError ? (
        <div className="rounded-lg border border-status-down/40 bg-status-down/10 px-4 py-3 text-sm text-status-down">
          {loadError}
        </div>
      ) : form ? (
        <div className="space-y-4">
          {!canWrite && (
            <p className="rounded-md border border-border bg-bg-secondary px-3 py-2 text-xs text-text-muted">
              {t('variables.site.readOnly', { defaultValue: 'You can view these values but not change them.' })}
            </p>
          )}
          {banner && (
            <div className="rounded-lg border border-status-down/40 bg-status-down/10 px-4 py-3 text-sm text-status-down">
              {banner}
            </div>
          )}

          {declared.length === 0 ? (
            <div className="rounded-lg border border-border bg-bg-secondary px-6 py-10 text-center text-sm text-text-secondary">
              {t('variables.site.noDeclared', {
                defaultValue: 'No published template asks for a value per site yet.',
              })}
            </div>
          ) : entryKeys.length === 0 ? (
            <div className="rounded-lg border border-border bg-bg-secondary px-6 py-8 text-center text-sm text-text-secondary">
              {t('variables.site.noEntry', {
                defaultValue: 'The templates in use ask for nothing to be typed per site. See below for where their values come from.',
              })}
            </div>
          ) : (
            <div className="divide-y divide-border rounded-lg border border-border bg-bg-secondary">
              {entryKeys.map((d) => {
                const spec = specs.get(d.key)!;
                const current = form.values[d.key];
                const editable = canWrite && d.siteWritable && !d.secrecyConflict;
                const marked = unset.has(d.key);
                return (
                  <div key={d.key} className={cn('grid grid-cols-1 gap-3 px-4 py-3 md:grid-cols-[2fr_3fr]', isDirty(d) && 'bg-accent/5')}>
                    <div>
                      <div className="flex items-center gap-1.5 text-sm font-medium text-text-primary">
                        {spec.kind === 'secret' && <KeyRound size={13} className="text-text-muted" />}
                        {d.label ?? d.key}
                      </div>
                      {d.label && <div className="font-mono text-[11px] text-text-muted">{d.key}</div>}
                      {spec.description && <div className="mt-1 text-xs text-text-secondary">{spec.description}</div>}
                      <div className="mt-1 text-xs text-text-muted">
                        {spec.kind === 'secret'
                          ? (current
                            ? (
                              <span className="inline-flex flex-wrap items-center gap-1.5">
                                {t('variables.site.secretSetHidden', { defaultValue: 'Set for this site (hidden)' })}
                                {current.isSecret && secretReveal?.(form.site.id, d.key, current.fingerprint)}
                              </span>
                            )
                            : t('variables.site.secretNotSet', { defaultValue: 'Not set for this site' }))
                          : current
                            ? t('variables.site.ownValue', { defaultValue: 'Value specific to this site' })
                            : spec.defaultValue !== undefined
                              ? t('variables.site.inheritsDefault', {
                                defaultValue: 'Not set here: inherited value, or by default {{value}}',
                                value: displayValue(spec.defaultValue),
                              })
                              : t('variables.site.inherits', { defaultValue: 'Not set here: the inherited value applies' })}
                      </div>
                    </div>
                    <div className="space-y-1">
                      {editable ? (
                        <>
                          <div className="flex items-start gap-2">
                            <div className={cn('flex-1', marked && 'opacity-40')}>{renderInput(d, spec, saving)}</div>
                            {current && (
                              <button
                                type="button"
                                onClick={() => {
                                  setUnset((prev) => {
                                    const n = new Set(prev);
                                    if (n.has(d.key)) n.delete(d.key); else n.add(d.key);
                                    return n;
                                  });
                                  setDrafts((prev) => { const n = { ...prev }; delete n[d.key]; return n; });
                                }}
                                className={cn(
                                  'mt-2 shrink-0 hover:text-text-primary',
                                  marked ? 'text-accent' : 'text-text-muted',
                                )}
                                title={marked
                                  ? t('variables.site.keepOwn', { defaultValue: 'Keep the site value' })
                                  : t('variables.site.useInherited', { defaultValue: 'Remove the site value and use the inherited one' })}
                              >
                                {marked ? <Undo2 size={15} /> : <RotateCcw size={15} />}
                              </button>
                            )}
                          </div>
                          {marked && (
                            <div className="text-xs text-accent">
                              {t('variables.site.willUnset', { defaultValue: 'Will be removed: the site will use the inherited value.' })}
                            </div>
                          )}
                        </>
                      ) : (
                        <div className="flex items-start gap-2 text-sm text-text-secondary">
                          <Lock size={13} className="mt-0.5 shrink-0 text-text-muted" />
                          <div>
                            {current && !current.isSecret && (
                              <div className="break-all font-mono text-text-primary">{displayValue(current.value)}</div>
                            )}
                            {(!d.siteWritable || d.secrecyConflict) && (
                              <div className="text-xs text-text-muted">{withheldReason(d)}</div>
                            )}
                          </div>
                        </div>
                      )}
                      {errors[d.key] && <div className="text-xs text-status-down">{errors[d.key]}</div>}
                    </div>
                  </div>
                );
              })}
            </div>
          )}

          {canWrite && entryKeys.length > 0 && (
            <div className="flex items-center gap-2">
              <Button size="sm" loading={saving} disabled={dirtyCount === 0} onClick={() => void save()}>
                {t('variables.site.saveCount', { defaultValue: 'Save changes ({{count}})', count: dirtyCount })}
              </Button>
              {dirtyCount > 0 && (
                <Button size="sm" variant="secondary" disabled={saving} onClick={reset}>
                  {t('common.cancel')}
                </Button>
              )}
            </div>
          )}

          {lockedKeys.length > 0 && (
            <details className="rounded-lg border border-border bg-bg-secondary">
              <summary className="cursor-pointer px-4 py-3 text-sm font-semibold text-text-primary">
                {t('variables.site.notEnteredHere', {
                  defaultValue: 'Not entered here ({{count}})',
                  count: lockedKeys.length,
                })}
              </summary>
              <ul className="divide-y divide-border border-t border-border">
                {lockedKeys.map((d) => {
                  const current = form.values[d.key];
                  return (
                    <li key={d.key} className="grid grid-cols-1 gap-2 px-4 py-3 md:grid-cols-[2fr_3fr]">
                      <div>
                        <div className="flex items-center gap-1.5 text-sm font-medium text-text-primary">
                          {d.secret && <KeyRound size={13} className="text-text-muted" />}
                          {d.label ?? d.key}
                        </div>
                        {d.label && <div className="font-mono text-[11px] text-text-muted">{d.key}</div>}
                      </div>
                      <div className="flex items-start gap-2 text-sm text-text-secondary">
                        <Lock size={13} className="mt-0.5 shrink-0 text-text-muted" />
                        <div>
                          {current && (
                            current.isSecret
                              ? (
                                <div className="flex flex-wrap items-center gap-1.5 text-xs text-text-muted">
                                  {t('variables.site.secretSetHidden', { defaultValue: 'Set for this site (hidden)' })}
                                  {secretReveal?.(form.site.id, d.key, current.fingerprint)}
                                </div>
                              )
                              : <div className="break-all font-mono text-text-primary">{displayValue(current.value)}</div>
                          )}
                          <div className="text-xs text-text-muted">{withheldReason(d)}</div>
                        </div>
                      </div>
                    </li>
                  );
                })}
              </ul>
            </details>
          )}

          {undeclared.length > 0 && (
            <div className="rounded-lg border border-border bg-bg-secondary p-4">
              <h3 className="mb-1 text-sm font-semibold text-text-primary">
                {t('variables.site.otherValues', { defaultValue: 'Other values set on this site' })}
              </h3>
              <p className="mb-2 text-xs text-text-muted">
                {t('variables.site.otherValuesHint', {
                  defaultValue: 'No published template asks for these values. They are shown for information only.',
                })}
              </p>
              <ul className="space-y-1 text-sm">
                {undeclared.map((v) => (
                  <li key={v.key} className="flex gap-3">
                    <span className="font-mono text-text-primary">{v.key}</span>
                    <span className="break-all text-text-secondary">
                      {v.isSecret
                        ? (
                          <span className="inline-flex flex-wrap items-center gap-1.5">
                            {t('variables.secretSetHidden', { defaultValue: 'Secret — set (hidden)' })}
                            {secretReveal?.(form.site.id, v.key, v.fingerprint)}
                          </span>
                        )
                        : <span className="font-mono">{displayValue(v.value)}</span>}
                    </span>
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>
      ) : null}
    </div>
  );
}
