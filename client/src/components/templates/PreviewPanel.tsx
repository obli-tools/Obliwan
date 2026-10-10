import { useEffect, useMemo, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { AlertTriangle, CheckCircle2, Eye, Info } from 'lucide-react';
import { MASTER_TENANT_ID, type DeviceBrand } from '@obliwan/shared';
import {
  templatesApi, type PreviewOverride, type RenderOptionsInput, type RevisionDraftInput, type TemplatePreview,
  type VarSchema,
} from '@/api/templates.api';
import { devicesApi } from '@/api/devices.api';
import { variablesApi } from '@/api/variables.api';
import { useGodView } from '@/store/godViewStore';
import type { Device } from '@/types/fleet';
import { Button } from '@/components/common/Button';
import { cn } from '@/utils/cn';
import { CodeEditor } from './CodeEditor';
import { defaultErrorText, levelLabel } from './labels';
import {
  planSamples, scratchSchemaFor, storedValuesOf, type SampleSlot, type StoredValues,
} from './previewPlan';
import { kindOf, parseSample, secretPlaceholder } from './varSchemaModel';

/**
 * Render the revision being edited on a WITNESS ROUTER, with sample values.
 *
 * ┌─ WHICH ENDPOINT, AND WHY ────────────────────────────────────────────────┐
 * │ `POST /templates/revisions/:id/preview` (TEMPLATE_READ) renders a STORED │
 * │ revision exactly as the fleet would: its body, its schema, the values    │
 * │ stored for the witness router. It is used whenever it can answer the     │
 * │ question — the revision is saved, nothing was edited since, no           │
 * │ placeholder is asked for, and no sample stands for a declared variable   │
 * │ of a stored level.                                                       │
 * │                                                                          │
 * │ Otherwise `POST /templates/preview` (TEMPLATE_WRITE) renders what is     │
 * │ on screen. A sampled variable KEEPS its declaration — so its level still │
 * │ applies — but loses `required` and `default` in the schema sent with it, │
 * │ and the sample is passed as an override. Its type is checked here, with  │
 * │ the same parser as the default column.                                   │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ A SAMPLE NEVER STANDS FOR A VALUE THE ROUTER ALREADY HAS ───────────────┐
 * │ An override reaches the render as an extra context key, and the server   │
 * │ refuses one that collides with anything it resolved for the router: a    │
 * │ value stored at ANY level of its chain — declared by this revision or    │
 * │ not — or a declaration's default. Removing the variable from the schema  │
 * │ does not avoid that. So the panel reads what the witness router resolves │
 * │ (`GET /variables/devices/:id`), offers a sample only where nothing is    │
 * │ stored, and LISTS what is stored instead. A variable declared `computed` │
 * │ or `bench` is the exception: the resolver sets a stored row for it      │
 * │ aside, so a sample is always its value.                                 │
 * │                                                                          │
 * │ On a SAVED revision (the only path without the right to write), a        │
 * │ render-time variable can be sampled only when the schema leaves its slot │
 * │ empty — not required, no default: a required one is reported missing    │
 * │ before any sample is looked at, and a default would collide.            │
 * │                                                                          │
 * │ SECRETS ARE NEVER TYPED HERE. A secret stored for the witness router     │
 * │ comes back as a placeholder: the render is REDACTED. For a secret        │
 * │ the router has no value for, "placeholders" (off by default) puts the    │
 * │ same placeholder in its place, so a template can be tried before every   │
 * │ secret exists. No credential travels either way.                         │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * The server has no preview without a router: the witness supplies `device.*`,
 * the inherited values of its site and group, and its OS version.
 */
interface PreviewPanelProps {
  brand: DeviceBrand | null;
  /** God view only: the workspace that owns the template (none for a library
   *  template, and never set outside the god view). */
  templateTenantId: number | null;
  /** The shipped library: owned by no workspace. */
  isLibrary: boolean;
  body: string;
  schema: VarSchema;
  renderOptions: RenderOptionsInput;
  /** Decides which resource kinds the render CLAIMS; sent with a scratch render. */
  sectionSeverity: RevisionDraftInput['sectionSeverity'];
  /** The saved revision, when there is one. */
  storedRevisionId: string | null;
  /** True when the screen holds edits that are not saved yet. */
  dirty: boolean;
  /** TEMPLATE_WRITE: may render an unsaved body. */
  canWrite: boolean;
  /** Names the body reads (`templateScanner`). */
  used: Map<string, number[]>;
  /** Facts a render on a router supplies by itself (`device`). */
  deviceRenderFacts: string[];
  /** Levels whose value is never stored (computed, bench): asked for as a
   *  sample, never read from the router's stored values. */
  renderTimeLevels: string[];
  onErrorLines: (lines: number[]) => void;
  onGoToLine: (line: number) => void;
}

const MAX_OVERRIDES = 50; // `renderPreviewSchema` / `scratchPreviewSchema`

const inputCls =
  'w-full rounded border border-border bg-bg-tertiary px-2 py-1 text-xs text-text-primary ' +
  'placeholder:text-text-muted focus:outline-none focus:ring-1 focus:ring-accent';

/** Every line a Nunjucks or worker message points at. */
export function errorLines(message: string | null): number[] {
  if (!message) return [];
  const out = new Set<number>();
  for (const m of message.matchAll(/\[Line (\d+), Column \d+\]/g)) out.add(Number(m[1]));
  for (const m of message.matchAll(/\bline (\d+)\b/gi)) out.add(Number(m[1]));
  return [...out].filter((n) => n > 0).sort((a, b) => a - b);
}

function serverError(err: unknown): string | null {
  return (err as { response?: { data?: { error?: string } } }).response?.data?.error ?? null;
}

export function PreviewPanel({
  brand, templateTenantId, isLibrary, body, schema, renderOptions, sectionSeverity, storedRevisionId, dirty, canWrite,
  used, deviceRenderFacts, renderTimeLevels, onErrorLines, onGoToLine,
}: PreviewPanelProps) {
  const { t } = useTranslation();
  const godView = useGodView();
  // In the god view the router list holds every workspace's routers, and the
  // stored preview renders in ONE: the template's own (the revision route
  // follows its row), the master tenant for a library template (a library row
  // moves nothing). A router of another workspace is refused there ("does not
  // exist in tenant"), so it is not offered. null: no narrowing — outside the
  // god view every router listed is the session's already, and a template
  // whose workspace this screen was not told keeps the full list.
  const witnessTenantId = !godView ? null : templateTenantId ?? (isLibrary ? MASTER_TENANT_ID : null);
  const [devices, setDevices] = useState<Device[] | null>(null);
  const [deviceId, setDeviceId] = useState<number | null>(null);
  const [samples, setSamples] = useState<Record<string, string>>({});
  // Off by default: a secret the router HAS already renders as a placeholder,
  // and one sent for it would collide with it.
  const [placeholders, setPlaceholders] = useState(false);
  const [showOptional, setShowOptional] = useState(false);
  const [auto, setAuto] = useState(false);
  const [running, setRunning] = useState(false);
  const [result, setResult] = useState<TemplatePreview | null>(null);
  const [failure, setFailure] = useState<string | null>(null);
  const [inputErrors, setInputErrors] = useState<string[]>([]);
  /** undefined: being read; null: could not be read. */
  const [stored, setStored] = useState<StoredValues | null | undefined>(undefined);

  // `filterTenantId` narrows a god-view list to the witness workspace (the
  // server ignores it for anyone else), and the rows are filtered on their
  // tenant again, so a list that came back wider never offers a foreign router.
  useEffect(() => {
    let alive = true;
    devicesApi.list({
      ...(brand ? { brand } : {}),
      ...(witnessTenantId !== null ? { filterTenantId: witnessTenantId } : {}),
    })
      .then((rows) => {
        if (!alive) return;
        const list = witnessTenantId === null ? rows : rows.filter((d) => d.tenantId === witnessTenantId);
        setDevices(list);
        // A router picked from a previous, wider list does not stay picked.
        setDeviceId((prev) => (prev !== null && list.some((d) => d.id === prev) ? prev : list[0]?.id ?? null));
      })
      .catch(() => { if (alive) setDevices([]); });
    return () => { alive = false; };
  }, [brand, witnessTenantId]);

  // What the witness router already resolves, read again for each router.
  useEffect(() => {
    setStored(undefined);
    if (!deviceId) return;
    let alive = true;
    variablesApi.forDevice(deviceId)
      .then((r) => { if (alive) setStored(storedValuesOf(r)); })
      .catch(() => { if (alive) setStored(null); });
    return () => { alive = false; };
  }, [deviceId]);

  const props = schema.properties ?? {};
  const isRenderTime = (k: string): boolean => {
    const level = props[k]?.['x-obliwan-level'];
    return typeof level === 'string' && renderTimeLevels.includes(level);
  };

  // What must be sampled for a router render, what may be, and what is
  // already set for the router and therefore listed, never sampled
  // (`previewPlan` states the rule).
  const { needed, optional, fromStore, missingSecrets, sampleKeys } = useMemo(
    () => planSamples({ used: used.keys(), schema, deviceRenderFacts, renderTimeLevels, canWrite, stored }),
    [used, schema, renderTimeLevels, deviceRenderFacts, canWrite, stored],
  );

  // Only what the panel currently offers is sent: a sample typed for a router
  // that had no value is not sent once another router, which has one, is
  // picked.
  const filledSamples = Object.entries(samples).filter(([k, v]) => sampleKeys.has(k) && v.trim() !== '');
  // A sample on a STORED-level declared variable goes through the scratch
  // path, where its declaration is kept without `required` and `default`. A
  // render-time sample on a saved revision is the only sampling a read-only
  // user gets (see the box above); with the right to write, it too goes
  // through the scratch path, where the sample is the value whatever the
  // declaration says.
  const samplesOnStored = filledSamples.some(([k]) => k in props && !isRenderTime(k));
  const samplesOnRenderTime = filledSamples.some(([k]) => k in props && isRenderTime(k));
  const usePlaceholders = canWrite && placeholders && missingSecrets.length > 0;
  const storedFits = !!storedRevisionId && !dirty && !usePlaceholders && !samplesOnStored
    && !(canWrite && samplesOnRenderTime);
  const mode: 'stored' | 'scratch' | 'blocked' = storedFits ? 'stored' : canWrite ? 'scratch' : 'blocked';

  const run = async () => {
    if (!deviceId || stored === undefined) return;
    setInputErrors([]);
    setFailure(null);

    // Typed samples -> JSON overrides. A refusal names the variable.
    const errors: string[] = [];
    const overrides: PreviewOverride[] = [];
    for (const [key, text] of filledSamples) {
      const parsed = parseSample(text, props[key]);
      if (!parsed.ok) errors.push(defaultErrorText(t, parsed.error, key));
      else overrides.push({ key, value: parsed.value });
    }
    if (usePlaceholders) {
      for (const key of missingSecrets) {
        if (!overrides.some((o) => o.key === key)) overrides.push({ key, value: secretPlaceholder(key) });
      }
    }
    if (overrides.length > MAX_OVERRIDES) {
      errors.push(t('templates.preview.tooManySamples', {
        defaultValue: 'At most {{max}} sample values can be sent at once ({{n}} here).',
        max: MAX_OVERRIDES, n: overrides.length,
      }));
    }
    if (errors.length > 0) { setInputErrors(errors); return; }

    setRunning(true);
    try {
      let out: TemplatePreview;
      if (mode === 'stored' && storedRevisionId) {
        out = await templatesApi.previewRevision(storedRevisionId, {
          deviceId,
          overrides: overrides.length > 0 ? overrides : undefined,
        });
      } else {
        out = await templatesApi.previewScratch({
          deviceId,
          body,
          varSchema: scratchSchemaFor(schema, new Set(overrides.map((o) => o.key))),
          sectionSeverity,
          renderOptions,
          overrides: overrides.length > 0 ? overrides : undefined,
        });
      }
      setResult(out);
      onErrorLines(out.ok ? [] : errorLines(out.errorMessage));
    } catch (err) {
      const message = serverError(err)
        ?? t('templates.preview.failed', { defaultValue: 'The preview could not be produced.' });
      setResult(null);
      setFailure(message);
      onErrorLines(errorLines(message));
    } finally {
      setRunning(false);
    }
  };

  // Optional automatic refresh, debounced: each render is a sandboxed worker
  // on the server, not something to start on every keystroke.
  const runRef = useRef(run);
  runRef.current = run;
  useEffect(() => {
    if (!auto || mode === 'blocked' || !deviceId || stored === undefined) return;
    const h = window.setTimeout(() => { void runRef.current(); }, 1500);
    return () => window.clearTimeout(h);
  }, [auto, body, schema, samples, placeholders, deviceId, mode, stored]);

  const sampleField = ({ key, prop, sampleable }: SampleSlot) => {
    const label = typeof prop?.['x-obliwan-label'] === 'string' ? (prop['x-obliwan-label'] as string) : null;
    const level = typeof prop?.['x-obliwan-level'] === 'string' ? (prop['x-obliwan-level'] as string) : null;
    const kind = prop ? kindOf(prop) : null;
    const value = samples[key] ?? '';
    const set = (v: string) => setSamples((s) => ({ ...s, [key]: v }));
    return (
      <div key={key} className="grid grid-cols-[minmax(0,1fr)_minmax(0,1.3fr)] items-start gap-2">
        <div className="min-w-0 pt-1">
          <div className="truncate text-xs text-text-primary">{label ?? key}</div>
          <div className="truncate font-mono text-[10px] text-text-muted">
            {key}{level ? ` · ${levelLabel(t, level)}` : ''}
          </div>
        </div>
        {!sampleable ? (
          <p className="pt-1 text-[11px] text-text-muted">
            {t('templates.preview.cannotSampleSaved', {
              defaultValue:
                'Required and supplied at render time: the preview of a saved revision cannot take a sample for it.',
            })}
          </p>
        ) : kind === 'boolean' ? (
          <select className={inputCls} value={value} onChange={(e) => set(e.target.value)}>
            <option value="">{t('templates.preview.noSample', { defaultValue: '— no sample' })}</option>
            <option value="true">{t('common.yes')}</option>
            <option value="false">{t('common.no')}</option>
          </select>
        ) : kind === 'enum' ? (
          <select className={inputCls} value={value} onChange={(e) => set(e.target.value)}>
            <option value="">{t('templates.preview.noSample', { defaultValue: '— no sample' })}</option>
            {(prop!.enum as unknown[]).map((v) => <option key={String(v)} value={String(v)}>{String(v)}</option>)}
          </select>
        ) : (
          <input
            className={cn(inputCls, 'font-mono')}
            value={value}
            placeholder={kind === 'array'
              ? t('templates.preview.listSample', { defaultValue: 'one value per line, or JSON' })
              : !prop
                ? t('templates.preview.factSample', { defaultValue: 'text, or JSON such as {"wifi_stack": "wifi"}' })
                : ''}
            onChange={(e) => set(e.target.value)}
          />
        )}
      </div>
    );
  };

  const lines = result && !result.ok ? errorLines(result.errorMessage) : errorLines(failure);

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-end gap-2">
        <label className="min-w-[14rem] flex-1 text-[11px] text-text-muted">
          {t('templates.preview.witness', { defaultValue: 'Witness router' })}
          <select
            className={cn(inputCls, 'mt-1')}
            value={deviceId ?? ''}
            onChange={(e) => setDeviceId(e.target.value ? Number(e.target.value) : null)}
            disabled={!devices || devices.length === 0}
          >
            {devices === null && <option value="">{t('common.loading')}</option>}
            {devices?.map((d) => (
              <option key={d.id} value={d.id}>
                {d.name}{d.model ? ` — ${d.model}` : ''}{d.osVersion ? ` — ${d.osVersion}` : ''}
              </option>
            ))}
          </select>
        </label>
        <Button
          type="button"
          size="sm"
          onClick={() => void run()}
          loading={running}
          disabled={!deviceId || mode === 'blocked' || stored === undefined}
        >
          <Eye size={14} className="mr-1" />
          {t('templates.preview.run', { defaultValue: 'Preview' })}
        </Button>
      </div>

      {devices !== null && devices.length === 0 && (
        <p className="rounded border border-border bg-bg-tertiary/40 p-2 text-xs text-text-secondary">
          {t('templates.preview.noDevice', {
            defaultValue:
              'No router of this brand in this customer: the preview needs a witness router to render on.',
          })}
        </p>
      )}

      <div className="flex flex-wrap gap-x-4 gap-y-1 text-[11px] text-text-secondary">
        {canWrite && missingSecrets.length > 0 && (
          <label className="inline-flex items-center gap-1.5">
            <input
              type="checkbox"
              className="h-3.5 w-3.5 accent-accent"
              checked={placeholders}
              onChange={(e) => setPlaceholders(e.target.checked)}
            />
            {t('templates.preview.placeholdersMissing', {
              defaultValue: 'Put a placeholder in for the secrets this router has no value for yet: {{list}}',
              list: missingSecrets.join(', '),
            })}
          </label>
        )}
        {canWrite && (
          <label className="inline-flex items-center gap-1.5">
            <input
              type="checkbox"
              className="h-3.5 w-3.5 accent-accent"
              checked={auto}
              onChange={(e) => setAuto(e.target.checked)}
            />
            {t('templates.preview.auto', { defaultValue: 'Refresh automatically' })}
          </label>
        )}
      </div>

      <p className="flex items-start gap-1.5 text-[11px] text-text-muted">
        <Info size={12} className="mt-0.5 shrink-0" />
        {mode === 'stored'
          ? t('templates.preview.modeStored', {
            defaultValue: 'Renders the SAVED revision, with the values stored for this router.',
          })
          : mode === 'scratch'
            ? t('templates.preview.modeScratch', {
              defaultValue: 'Renders what is on screen (including unsaved changes), with your sample values.',
            })
            : t('templates.preview.modeBlockedUnsaved', {
              defaultValue: 'Rendering something that is not saved yet needs the right to write templates.',
            })}
      </p>

      {stored === null && (
        <p className="flex items-start gap-1.5 text-[11px] text-status-ssl-warning">
          <AlertTriangle size={12} className="mt-0.5 shrink-0" />
          {t('templates.preview.storedUnknown', {
            defaultValue:
              'The values stored for this router could not be read: a sample for a variable that already has a value will be refused.',
          })}
        </p>
      )}

      {needed.length > 0 && (
        <div className="space-y-1.5 rounded border border-border p-2">
          <p className="text-[11px] font-medium text-text-secondary">
            {t('templates.preview.neededTitle', {
              defaultValue: 'Values a router render does not have — give a sample to try the template:',
            })}
          </p>
          {needed.map((n) => sampleField(n))}
        </div>
      )}

      {fromStore.length > 0 && (
        <p className="text-[11px] text-text-muted">
          {t('templates.preview.fromStore', {
            defaultValue: 'Already set for this router, rendered as they are: {{list}}',
            list: fromStore.map((s) => (s.sourceName ? `${s.key} (${s.sourceName})` : s.key)).join(', '),
          })}
        </p>
      )}

      {optional.length > 0 && (
        <div className="rounded border border-border p-2">
          <button
            type="button"
            className="text-[11px] font-medium text-accent hover:underline"
            onClick={() => setShowOptional((v) => !v)}
          >
            {showOptional
              ? t('templates.preview.hideOptional', { defaultValue: 'Hide the other variables' })
              : t('templates.preview.showOptionalUnset', {
                defaultValue: 'Try values for the variables this router has none for ({{n}})', n: optional.length,
              })}
          </button>
          {showOptional && (
            <div className="mt-2 space-y-1.5">
              <p className="text-[11px] text-text-muted">
                {t('templates.preview.optionalHintUnset', {
                  defaultValue:
                    'Only the variables with no value stored for this router are listed. Left empty, a variable takes its default, if it has one.',
                })}
              </p>
              {optional.map((o) => sampleField(o))}
            </div>
          )}
        </div>
      )}

      {inputErrors.length > 0 && (
        <ul className="space-y-0.5 rounded border border-status-down/50 bg-status-down/10 p-2 text-xs text-status-down">
          {inputErrors.map((e) => <li key={e}>{e}</li>)}
        </ul>
      )}

      {failure && (
        <div className="rounded border border-status-down/50 bg-status-down/10 p-2 text-xs">
          <p className="flex items-center gap-1.5 font-semibold text-status-down">
            <AlertTriangle size={13} />
            {t('templates.preview.refused', { defaultValue: 'The preview was refused' })}
          </p>
          <p className="mt-1 whitespace-pre-wrap break-words text-text-secondary">{failure}</p>
        </div>
      )}

      {result && !result.ok && (
        <div className="space-y-1.5 rounded border border-status-down/50 bg-status-down/10 p-2 text-xs">
          <p className="flex items-center gap-1.5 font-semibold text-status-down">
            <AlertTriangle size={13} />
            {result.errorKind === 'variables'
              ? t('templates.preview.errVariables', { defaultValue: 'Some variables have no value for this router' })
              : result.errorKind === 'parse'
                ? t('templates.preview.errParse', {
                  defaultValue: 'The template rendered, but ObliWAN could not read the configuration it produced',
                })
                : t('templates.preview.errTemplate', { defaultValue: 'The template has an error' })}
          </p>
          {result.missing.length > 0 && (
            <ul className="space-y-0.5 text-text-secondary">
              {result.missing.map((m) => (
                <li key={m.key}>
                  {t('templates.preview.missingVar', {
                    defaultValue: '"{{key}}" has no value — set it at the level: {{level}}',
                    key: m.key, level: levelLabel(t, m.expectedScope),
                  })}
                </li>
              ))}
            </ul>
          )}
          {result.typeErrors.length > 0 && (
            <ul className="space-y-0.5 text-text-secondary">
              {result.typeErrors.map((e) => (
                <li key={`${e.key}:${e.message}`}>
                  {t('templates.preview.typeError', {
                    defaultValue: '"{{key}}" (set at {{source}}): {{message}}',
                    key: e.key, source: e.sourceName, message: e.message,
                  })}
                </li>
              ))}
            </ul>
          )}
          {result.errorMessage && (
            <p className="whitespace-pre-wrap break-words font-mono text-[11px] text-text-secondary">
              {result.errorMessage}
            </p>
          )}
        </div>
      )}

      {lines.length > 0 && (
        <div className="flex flex-wrap items-center gap-1.5 text-[11px] text-text-secondary">
          {t('templates.preview.goToLine', { defaultValue: 'Go to line:' })}
          {lines.map((l) => (
            <button
              key={l}
              type="button"
              className="rounded border border-border px-1.5 font-mono text-accent hover:bg-bg-hover"
              onClick={() => onGoToLine(l)}
            >
              {l}
            </button>
          ))}
        </div>
      )}

      {result && result.ok && (
        <div className="space-y-2">
          <p className="flex flex-wrap items-center gap-1.5 text-xs text-status-up">
            <CheckCircle2 size={13} />
            {t('templates.preview.ok', { defaultValue: 'Rendered' })}
            {result.durationMs !== null && (
              <span className="text-text-muted">
                {t('templates.preview.duration', { defaultValue: 'in {{ms}} ms', ms: result.durationMs })}
              </span>
            )}
            <span className="text-text-muted">
              · {t('templates.preview.redacted', { defaultValue: 'secrets are shown as placeholders' })}
            </span>
          </p>
          {Object.keys(result.resourceCounts).length > 0 && (
            <p className="text-[11px] text-text-muted">
              {t('templates.preview.resources', { defaultValue: 'Recognised:' })}{' '}
              {Object.entries(result.resourceCounts).map(([k, n]) => `${k} ${n}`).join(' · ')}
            </p>
          )}
          {result.unclaimedSections.length > 0 && (
            <p className="text-[11px] text-text-muted">
              {t('templates.preview.unclaimed', {
                defaultValue: "Sections the template writes that ObliWAN's configuration model does not cover: {{list}}",
                list: result.unclaimedSections.join(', '),
              })}
            </p>
          )}
          {result.warnings.length > 0 && (
            <ul className="space-y-0.5 text-[11px] text-status-ssl-warning">
              {result.warnings.map((w) => <li key={w}>{w}</li>)}
            </ul>
          )}
          <CodeEditor
            value={result.body ?? ''}
            readOnly
            ariaLabel={t('templates.preview.outputAria', { defaultValue: 'Rendered configuration' })}
            className="h-[22rem]"
          />
        </div>
      )}
    </div>
  );
}
