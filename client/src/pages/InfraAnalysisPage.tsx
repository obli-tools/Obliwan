import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import toast from 'react-hot-toast';
import { Download, Network, Play, RefreshCw, ScanSearch, Trash2 } from 'lucide-react';
import type {
  InfraAnalysisApplyResult,
  InfraAnalysisCandidates,
  InfraAnalysisPreviewRequest,
  InfraAnalysisSnapshot,
  InfraDeviceResult,
  InfraFound,
  InfraVariableResult,
  InfraVerdict,
  JsonValue,
} from '@obliwan/shared';
import { Button } from '@/components/common/Button';
import { Input } from '@/components/common/Input';
import { LanRepriseModal } from '@/components/allocation/LanRepriseModal';
import { cn } from '@/utils/cn';
import { useTenantStore } from '@/store/tenantStore';
import { downloadText } from '@/api/query.api';
import { apiErrorText } from '@/components/variables/valueKinds';
import { infraAnalysisApi, infraAnalysisErrorCode } from '@/api/infraAnalysis.api';

/**
 * Infrastructure analysis — what the routers in service actually run, in the
 * terms of the template's site variables.
 *
 * A page of its own rather than a tab of Quick Setup Tenant: Quick Setup's
 * tabs are views of ONE draft request that one Check and one Apply judge
 * together, while an analysis has a lifecycle of its own — a background read
 * of a few hundred routers, polled, whose results (secrets included) are held
 * on the server for fifteen minutes. Its variables export is a file Quick
 * Setup's Files tab loads, and its LAN rows go to the LAN reprise.
 *
 * ┌─ WHAT THIS SCREEN PROMISES ──────────────────────────────────────────────┐
 * │ • "Run" reads routers, READ-ONLY, and writes nothing in ObliWAN.         │
 * │ • A typed account lives in this component's state and the one request   │
 * │   that starts the run; the server never stores it.                     │
 * │ • No secret is ever shown: a password read is "found (to the vault on   │
 * │   apply)". The server holds it, and the variables export leaves its      │
 * │   cell empty.                                                            │
 * │ • "Apply" writes only the rows ticked, as SITE variables, each judged    │
 * │   again by the server; refusals are listed by site and variable.         │
 * └──────────────────────────────────────────────────────────────────────────┘
 */

const CARD = 'mb-4 rounded-xl border border-border bg-bg-secondary p-4';
const TH = 'px-2 py-1.5 text-left text-xs font-medium text-text-muted';
const TD = 'px-2 py-1.5 text-sm text-text-primary align-top';
const POLL_MS = 1500;

type SelectionMode = 'all' | 'range' | 'pick';
type Filter = 'proposals' | 'all' | 'problems';

const VERDICT_STYLE: Record<InfraVerdict, string> = {
  same: 'bg-bg-tertiary text-text-muted',
  differs: 'bg-amber-500/15 text-amber-400',
  new: 'bg-emerald-500/15 text-emerald-400',
  invalid: 'bg-red-500/15 text-red-400',
  conflict: 'bg-red-500/15 text-red-400',
  none: 'bg-bg-tertiary text-text-muted',
};

function valueText(v: JsonValue | undefined): string {
  if (v === undefined) return '';
  if (typeof v === 'string') return v;
  return JSON.stringify(v);
}

function rowKey(siteId: number, key: string): string {
  return `${siteId}|${key}`;
}

/** Items of the probe's menu its `where` did not select (a PPPoE client on
 *  another port, a disabled one). A finding even when the row's own verdict
 *  is quiet: "dhcp, same" beside a PPPoE client on ether2 says the template's
 *  idea of this store may be wrong, and nothing else on the row says so. */
function hasElsewhere(v: InfraVariableResult): boolean {
  return v.elsewhere.length > 0;
}

function isProblem(v: InfraVariableResult): boolean {
  return v.verdict === 'invalid' || v.verdict === 'conflict' || v.found.status === 'unreadable' || v.found.status === 'ambiguous'
    || hasElsewhere(v);
}

export function InfraAnalysisPage() {
  const { t } = useTranslation();
  const currentTenantId = useTenantStore((s) => s.currentTenantId);
  const tenants = useTenantStore((s) => s.tenants);
  const tenantName = tenants.find((x) => x.id === currentTenantId)?.name ?? null;

  const [candidates, setCandidates] = useState<InfraAnalysisCandidates | null>(null);
  const [loadingCandidates, setLoadingCandidates] = useState(false);
  const [mode, setMode] = useState<SelectionMode>('all');
  const [from, setFrom] = useState('');
  const [to, setTo] = useState('');
  const [picked, setPicked] = useState<Set<number>>(new Set());
  const [search, setSearch] = useState('');
  const [revisionId, setRevisionId] = useState('');
  const [lanInterface, setLanInterface] = useState('');
  const [useCredential, setUseCredential] = useState(false);
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [readSecrets, setReadSecrets] = useState(false);

  const [snapshot, setSnapshot] = useState<InfraAnalysisSnapshot | null>(null);
  const [expired, setExpired] = useState(false);
  const [starting, setStarting] = useState(false);
  const [filter, setFilter] = useState<Filter>('proposals');
  const [rowSearch, setRowSearch] = useState('');
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [applying, setApplying] = useState(false);
  const [applyResult, setApplyResult] = useState<InfraAnalysisApplyResult | null>(null);
  const [lanCsv, setLanCsv] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const pollRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const errorText = useCallback(
    (err: unknown): string => {
      const code = infraAnalysisErrorCode(err);
      if (code) return t(`infraAnalysis.error.${code}`, { defaultValue: apiErrorText(err) ?? code });
      return apiErrorText(err) ?? (err instanceof Error ? err.message : String(err));
    },
    [t],
  );

  const loadCandidates = useCallback(async () => {
    setLoadingCandidates(true);
    try {
      setCandidates(await infraAnalysisApi.candidates());
    } catch (err) {
      setError(errorText(err));
    } finally {
      setLoadingCandidates(false);
    }
  }, [errorText]);

  // A workspace switch starts the page over: an analysis is one workspace's.
  useEffect(() => {
    setSnapshot(null);
    setSelected(new Set());
    setApplyResult(null);
    setPicked(new Set());
    setRevisionId('');
    setExpired(false);
    if (currentTenantId !== null) void loadCandidates();
  }, [currentTenantId, loadCandidates]);

  // Poll while the run goes on.
  useEffect(() => {
    if (!snapshot || snapshot.status !== 'running') return undefined;
    pollRef.current = setTimeout(() => {
      infraAnalysisApi
        .get(snapshot.analysisId)
        .then((s) => setSnapshot(s))
        .catch((err: unknown) => {
          if (infraAnalysisErrorCode(err) === 'NOT_FOUND') {
            setExpired(true);
            setSnapshot(null);
          } else {
            setError(errorText(err));
          }
        });
    }, POLL_MS);
    return () => {
      if (pollRef.current) clearTimeout(pollRef.current);
    };
  }, [snapshot, errorText]);

  const devices = candidates?.devices ?? [];
  const visibleCandidates = useMemo(() => {
    const q = search.trim().toLowerCase();
    if (q === '') return devices;
    return devices.filter((d) => d.deviceName.toLowerCase().includes(q) || (d.site?.code ?? '').toLowerCase().includes(q)
      || (d.site?.name ?? '').toLowerCase().includes(q));
  }, [devices, search]);

  const typedCredential = useCredential && (username.trim() !== '' || password !== '');
  const credentialIncomplete = typedCredential && (username.trim() === '' || password === '');
  const selectionReady = mode === 'all' || (mode === 'range' && (from.trim() !== '' || to.trim() !== '')) || (mode === 'pick' && picked.size > 0);
  const running = snapshot?.status === 'running';

  const start = async (): Promise<void> => {
    setError(null);
    setExpired(false);
    setApplyResult(null);
    setSelected(new Set());
    const body: InfraAnalysisPreviewRequest = {
      selection:
        mode === 'all'
          ? { all: true }
          : mode === 'range'
            ? { ...(from.trim() ? { siteCodeFrom: from.trim() } : {}), ...(to.trim() ? { siteCodeTo: to.trim() } : {}) }
            : { deviceIds: [...picked] },
      readSecrets,
      ...(revisionId ? { revisionId } : {}),
      ...(lanInterface.trim() ? { lanInterface: lanInterface.trim() } : {}),
      ...(typedCredential && !credentialIncomplete ? { credential: { username: username.trim(), password } } : {}),
    };
    setStarting(true);
    try {
      setSnapshot(await infraAnalysisApi.preview(body));
    } catch (err) {
      setError(errorText(err));
    } finally {
      setStarting(false);
    }
  };

  const forget = async (): Promise<void> => {
    if (!snapshot) return;
    try {
      await infraAnalysisApi.forget(snapshot.analysisId);
      toast.success(t('infraAnalysis.forgotten', { defaultValue: 'Analysis forgotten, secrets dropped.' }));
    } catch (err) {
      if (infraAnalysisErrorCode(err) !== 'NOT_FOUND') setError(errorText(err));
    }
    setSnapshot(null);
    setSelected(new Set());
    setApplyResult(null);
  };

  // ── Results ──────────────────────────────────────────────────────────────
  interface Row {
    device: InfraDeviceResult;
    variable: InfraVariableResult | null;
  }
  const sortedDevices = useMemo(() => {
    if (!snapshot) return [];
    return [...snapshot.devices].sort((a, b) => {
      const ca = a.site?.code ?? '￿';
      const cb = b.site?.code ?? '￿';
      return ca.localeCompare(cb, undefined, { numeric: true }) || a.deviceName.localeCompare(b.deviceName);
    });
  }, [snapshot]);

  const rows = useMemo(() => {
    const q = rowSearch.trim().toLowerCase();
    const out: Row[] = [];
    for (const d of sortedDevices) {
      if (q !== '' && !(`${d.site?.code ?? ''} ${d.site?.name ?? ''} ${d.deviceName}`.toLowerCase().includes(q))) continue;
      if (d.state !== 'done') {
        if (filter !== 'proposals') out.push({ device: d, variable: null });
        continue;
      }
      for (const v of d.variables) {
        // The default view: what an apply would do, and the rows whose probe
        // saw something it did not select — the one finding no verdict carries.
        if (filter === 'proposals' && v.action === null && !hasElsewhere(v)) continue;
        if (filter === 'problems' && !isProblem(v)) continue;
        out.push({ device: d, variable: v });
      }
    }
    return out;
  }, [sortedDevices, filter, rowSearch]);

  // "Select every proposal" never takes a row that would change a value stored
  // FOR THE SITE (a wan1_mode=static typed by hand, a site secret): those are
  // ticked one by one. The row stays visible and selectable.
  const { proposals, siteOverwrites } = useMemo(() => {
    const keys = new Set<string>();
    let overwrites = 0;
    for (const d of snapshot?.devices ?? []) {
      if (d.state !== 'done' || !d.site) continue;
      for (const v of d.variables) {
        if (v.action === null || v.appliedAt) continue;
        if (v.verdict === 'differs' && v.stored.level === 'site') { overwrites += 1; continue; }
        keys.add(rowKey(d.site.id, v.key));
      }
    }
    return { proposals: keys, siteOverwrites: overwrites };
  }, [snapshot]);

  const toggle = (k: string): void => {
    setSelected((s) => {
      const n = new Set(s);
      if (n.has(k)) n.delete(k);
      else n.add(k);
      return n;
    });
  };

  const apply = async (): Promise<void> => {
    if (!snapshot || selected.size === 0) return;
    const ok = window.confirm(
      t('infraAnalysis.applyConfirm', {
        defaultValue: 'Write {{count}} value(s) as site variables? Secrets go to the vault. Nothing is written to any router.',
        count: selected.size,
      }),
    );
    if (!ok) return;
    setApplying(true);
    setError(null);
    try {
      const rowsToApply = [...selected].map((k) => {
        const i = k.indexOf('|');
        return { siteId: Number(k.slice(0, i)), key: k.slice(i + 1) };
      });
      const res = await infraAnalysisApi.apply({ analysisId: snapshot.analysisId, rows: rowsToApply });
      setApplyResult(res);
      toast.success(t('infraAnalysis.appliedToast', { defaultValue: '{{sites}} site(s) written', sites: res.written.length }));
      setSelected(new Set());
      setSnapshot(await infraAnalysisApi.get(snapshot.analysisId));
    } catch (err) {
      if (infraAnalysisErrorCode(err) === 'NOT_FOUND') {
        setExpired(true);
        setSnapshot(null);
      } else {
        setError(errorText(err));
      }
    } finally {
      setApplying(false);
    }
  };

  const exportFile = async (kind: 'variables' | 'lan' | 'lanReprise'): Promise<void> => {
    if (!snapshot) return;
    try {
      const ex = await infraAnalysisApi.exportFiles(snapshot.analysisId);
      if (kind === 'lanReprise') {
        setLanCsv(ex.lan.csv);
        return;
      }
      const file = kind === 'variables' ? ex.variables : ex.lan;
      downloadText(file.filename, 'text/csv', file.csv);
    } catch (err) {
      if (infraAnalysisErrorCode(err) === 'NOT_FOUND') {
        setExpired(true);
        setSnapshot(null);
      } else {
        setError(errorText(err));
      }
    }
  };

  const foundText = (f: InfraFound): string => {
    switch (f.status) {
      case 'found':
        return valueText(f.value);
      case 'secret_found':
        return t('infraAnalysis.found.secret', { defaultValue: 'found (to the vault on apply)' });
      case 'omitted':
        return t('infraAnalysis.found.omitted', { defaultValue: 'same as {{key}} (inherited)', key: f.equalsKey });
      case 'not_found':
        return t('infraAnalysis.found.not_found', { defaultValue: 'not found' });
      case 'not_seen':
        // A present-only probe matched nothing: an absence, which proposes
        // and confirms nothing (a fixed-IP store reads like a DHCP one).
        return t('infraAnalysis.found.not_seen', { defaultValue: 'nothing seen — an absence proposes nothing' });
      case 'ambiguous':
        return t('infraAnalysis.found.ambiguous', { defaultValue: 'ambiguous ({{count}} items)', count: f.count });
      case 'not_read':
        return t('infraAnalysis.found.not_read', { defaultValue: 'not read (secrets not asked for)' });
      case 'unreadable':
        return t('infraAnalysis.found.unreadable', {
          defaultValue: 'unreadable: {{reason}}',
          reason: t(`infraAnalysis.unreadable.${f.reason}`, { defaultValue: f.reason }),
        });
      default:
        return '';
    }
  };

  const storedText = (v: InfraVariableResult): string => {
    if (!v.stored.present) return t('infraAnalysis.stored.none', { defaultValue: 'nothing' });
    const level = t(`infraAnalysis.level.${v.stored.level ?? 'default'}`, { defaultValue: v.stored.level ?? '' });
    const what = v.stored.isSecret ? t('infraAnalysis.stored.secret', { defaultValue: 'secret stored' }) : valueText(v.stored.value);
    return `${what} — ${t('infraAnalysis.stored.level', { defaultValue: 'at {{level}}', level })}`;
  };

  const counts = snapshot?.counts;
  const lanRows = sortedDevices.filter((d) => d.state === 'done' && d.lan);

  return (
    <div className="p-6">
      <div className="mb-5 flex flex-wrap items-center justify-between gap-2">
        <h1 className="flex items-center gap-2 text-2xl font-semibold text-text-primary">
          <ScanSearch size={22} /> {t('infraAnalysis.title', { defaultValue: 'Infrastructure analysis' })}
        </h1>
        <Button size="sm" variant="secondary" onClick={() => void loadCandidates()} loading={loadingCandidates}>
          <RefreshCw size={14} /> {t('infraAnalysis.refresh', { defaultValue: 'Refresh the device list' })}
        </Button>
      </div>
      {tenantName && (
        <p className="mb-1 text-sm text-text-primary">
          {t('infraAnalysis.workspace', { defaultValue: 'Workspace: {{tenant}}', tenant: tenantName })}
        </p>
      )}
      <p className="mb-4 text-xs text-text-muted">
        {t('infraAnalysis.help', {
          defaultValue:
            "Reads, on each router of this workspace already in service, the values of the site variables its template says how to find (x-obliwan-discover), and the store LAN, then proposes them per site. Read-only: each router is read over its SSH channel and nothing is written to it. Apply writes the rows you select as site variables.",
        })}
      </p>

      {error && <div className="mb-4 rounded-md border border-red-500/40 bg-red-500/10 p-3 text-sm text-red-400">{error}</div>}
      {expired && (
        <div className="mb-4 rounded-md border border-amber-500/40 bg-amber-500/10 p-3 text-sm text-amber-400">
          {t('infraAnalysis.expired', { defaultValue: 'This analysis has expired (or was forgotten): run it again.' })}
        </div>
      )}

      {/* ── What to read ── */}
      <div className={CARD}>
        <h2 className="mb-3 text-sm font-semibold text-text-primary">{t('infraAnalysis.settings', { defaultValue: 'What to read' })}</h2>
        <div className="grid gap-4 lg:grid-cols-2">
          <div className="space-y-2">
            <p className="text-sm font-medium text-text-secondary">{t('infraAnalysis.selection.label', { defaultValue: 'Devices' })}</p>
            {(['all', 'range', 'pick'] as const).map((m) => (
              <label key={m} className="flex items-center gap-2 text-sm text-text-primary">
                <input type="radio" name="infra-selection" checked={mode === m} onChange={() => setMode(m)} />
                {m === 'all'
                  ? t('infraAnalysis.selection.all', { defaultValue: 'Every MikroTik router of the workspace ({{count}})', count: devices.length })
                  : m === 'range'
                    ? t('infraAnalysis.selection.range', { defaultValue: 'A range of site codes' })
                    : t('infraAnalysis.selection.pick', { defaultValue: 'A selection' })}
              </label>
            ))}
            {mode === 'range' && (
              <div className="grid grid-cols-2 gap-2 pl-6">
                <Input id="infra-from" label={t('infraAnalysis.selection.from', { defaultValue: 'From code' })} value={from} onChange={(e) => setFrom(e.target.value)} />
                <Input id="infra-to" label={t('infraAnalysis.selection.to', { defaultValue: 'To code' })} value={to} onChange={(e) => setTo(e.target.value)} />
              </div>
            )}
            {mode === 'pick' && (
              <div className="space-y-2 pl-6">
                <Input
                  id="infra-search"
                  placeholder={t('infraAnalysis.selection.search', { defaultValue: 'Filter by site or name' })}
                  value={search}
                  onChange={(e) => setSearch(e.target.value)}
                />
                <div className="max-h-56 overflow-auto rounded-md border border-border">
                  {visibleCandidates.map((d) => (
                    <label key={d.deviceId} className="flex items-start gap-2 border-b border-border px-2 py-1 text-sm last:border-b-0">
                      <input
                        type="checkbox"
                        className="mt-0.5"
                        checked={picked.has(d.deviceId)}
                        onChange={() =>
                          setPicked((s) => {
                            const n = new Set(s);
                            if (n.has(d.deviceId)) n.delete(d.deviceId);
                            else n.add(d.deviceId);
                            return n;
                          })
                        }
                      />
                      <span className="flex-1">
                        <span className="font-mono">{d.site?.code ?? '—'}</span> {d.deviceName}
                        {d.skip && (
                          <span className="block text-xs text-amber-400">
                            {t('infraAnalysis.selection.skip', {
                              defaultValue: 'would be skipped: {{reason}}',
                              reason: t(`infraAnalysis.device.reason.${d.skip}`, { defaultValue: d.skip }),
                            })}
                          </span>
                        )}
                      </span>
                    </label>
                  ))}
                </div>
                <p className="text-xs text-text-muted">
                  {t('infraAnalysis.selection.selected', { defaultValue: '{{count}} selected', count: picked.size })}
                </p>
              </div>
            )}
          </div>

          <div className="space-y-3">
            <div className="space-y-1">
              <label htmlFor="infra-revision" className="block text-sm font-medium text-text-secondary">
                {t('infraAnalysis.revision.label', { defaultValue: 'Template revision' })}
              </label>
              <select
                id="infra-revision"
                value={revisionId}
                onChange={(e) => setRevisionId(e.target.value)}
                className="w-full rounded-md border border-border bg-bg-tertiary px-3 py-2 text-sm text-text-primary"
              >
                <option value="">{t('infraAnalysis.revision.own', { defaultValue: "Each device's own (its template assignment)" })}</option>
                {(candidates?.revisions ?? []).map((r) => (
                  <option key={r.id} value={r.id}>
                    {t('infraAnalysis.revision.option', {
                      defaultValue: '{{name}} — revision {{revision}} ({{status}}), {{count}} probe(s)',
                      name: r.templateName,
                      revision: r.revision,
                      status: r.status,
                      count: r.probeKeys.length,
                    })}
                  </option>
                ))}
              </select>
              {candidates && candidates.revisions.length === 0 && (
                <p className="text-xs text-amber-400">
                  {t('infraAnalysis.revision.none', {
                    defaultValue: 'No template revision of this workspace declares probes (x-obliwan-discover): only the LAN is read.',
                  })}
                </p>
              )}
            </div>
            <div>
              <Input
                id="infra-lan-interface"
                label={t('infraAnalysis.lanInterface.label', { defaultValue: 'LAN interface (optional)' })}
                placeholder="bridge-lan"
                value={lanInterface}
                onChange={(e) => setLanInterface(e.target.value)}
              />
              <p className="mt-1 text-xs text-text-muted">
                {t('infraAnalysis.lanInterface.hint', {
                  defaultValue: 'Empty: the one bridge carrying an address, preferring a member of the LAN interface list.',
                })}
              </p>
            </div>
            <label className="flex items-start gap-2 text-sm text-text-primary">
              <input type="checkbox" className="mt-0.5" checked={useCredential} onChange={(e) => setUseCredential(e.target.checked)} />
              <span>
                {t('infraAnalysis.credential.toggle', { defaultValue: 'Log in with another account for this run (not stored)' })}
                <span className="block text-xs text-text-muted">
                  {t('infraAnalysis.credential.hint', {
                    defaultValue: "Unticked: each device's own SSH channel. A typed account is used for this run only and is never stored.",
                  })}
                </span>
              </span>
            </label>
            {useCredential && (
              <div className="grid grid-cols-2 gap-2 pl-6">
                <Input
                  id="infra-username"
                  label={t('infraAnalysis.credential.username', { defaultValue: 'Username' })}
                  value={username}
                  autoComplete="off"
                  onChange={(e) => setUsername(e.target.value)}
                />
                <Input
                  id="infra-password"
                  type="password"
                  label={t('infraAnalysis.credential.password', { defaultValue: 'Password' })}
                  value={password}
                  autoComplete="new-password"
                  onChange={(e) => setPassword(e.target.value)}
                />
              </div>
            )}
            <label className="flex items-start gap-2 text-sm text-text-primary">
              <input type="checkbox" className="mt-0.5" checked={readSecrets} onChange={(e) => setReadSecrets(e.target.checked)} />
              <span>
                {t('infraAnalysis.readSecrets', {
                  defaultValue: 'Also read the secrets (PPPoE passwords) — needs an account with the sensitive right',
                })}
                <span className="block text-xs text-text-muted">
                  {t('infraAnalysis.readSecretsHint', {
                    defaultValue:
                      "Read only where the SSH account's group holds RouterOS's sensitive policy. A secret read stays on the server for this analysis (15 minutes), is never shown, and goes to the vault on apply.",
                  })}
                </span>
              </span>
            </label>
          </div>
        </div>
        <div className="mt-4 flex flex-wrap items-center gap-2">
          <Button
            size="sm"
            onClick={() => void start()}
            loading={starting}
            disabled={starting || running || !selectionReady || credentialIncomplete || currentTenantId === null}
          >
            <Play size={14} /> {t('infraAnalysis.run', { defaultValue: 'Run the analysis' })}
          </Button>
          {credentialIncomplete && (
            <span className="text-xs text-amber-400">
              {t('infraAnalysis.credential.incomplete', { defaultValue: 'Give both the username and the password, or untick.' })}
            </span>
          )}
        </div>
      </div>

      {/* ── Progress and results ── */}
      {snapshot && (
        <div className={CARD}>
          <div className="mb-3 flex flex-wrap items-center gap-3">
            {running ? (
              <div className="flex-1">
                <p className="text-sm text-text-primary">
                  {t('infraAnalysis.running', {
                    defaultValue: 'Reading… {{done}} / {{total}} device(s)',
                    done: snapshot.progress.done,
                    total: snapshot.progress.total,
                  })}
                </p>
                <div className="mt-1 h-1.5 w-full overflow-hidden rounded bg-bg-tertiary">
                  <div
                    className="h-full bg-accent transition-all"
                    style={{ width: `${snapshot.progress.total === 0 ? 0 : (100 * snapshot.progress.done) / snapshot.progress.total}%` }}
                  />
                </div>
              </div>
            ) : (
              counts && (
                <p className="flex-1 text-sm text-text-primary">
                  {t('infraAnalysis.counts', {
                    defaultValue: '{{done}} read, {{skipped}} skipped, {{failed}} failed — {{proposals}} proposal(s), {{lan}} LAN(s) found',
                    done: counts.done,
                    skipped: counts.skipped,
                    failed: counts.failed,
                    proposals: counts.proposals,
                    lan: counts.lanFound,
                  })}
                  {counts.elsewhere > 0 && (
                    <button
                      type="button"
                      onClick={() => setFilter('problems')}
                      className="block text-left text-xs text-amber-400 hover:underline"
                    >
                      {t('infraAnalysis.countsElsewhere', {
                        defaultValue:
                          '{{count}} router(s) with an item the probes did not select (another port, a disabled client) — show the problems',
                        count: counts.elsewhere,
                      })}
                    </button>
                  )}
                </p>
              )
            )}
            <span className="text-xs text-text-muted">
              {t('infraAnalysis.expires', {
                defaultValue: 'Kept until {{time}}, secrets included.',
                time: new Date(snapshot.expiresAt).toLocaleTimeString(),
              })}
            </span>
            <Button size="sm" variant="ghost" onClick={() => void forget()} disabled={running}>
              <Trash2 size={14} /> {t('infraAnalysis.forget', { defaultValue: 'Forget this analysis' })}
            </Button>
          </div>

          {!running && (
            <>
              <div className="mb-3 flex flex-wrap items-center gap-2">
                <span className="text-xs text-text-muted">{t('infraAnalysis.filter.label', { defaultValue: 'Show' })}</span>
                {(['proposals', 'problems', 'all'] as const).map((f) => (
                  <button
                    key={f}
                    type="button"
                    onClick={() => setFilter(f)}
                    className={cn(
                      'rounded-full px-2.5 py-0.5 text-xs',
                      filter === f ? 'bg-accent/15 text-accent' : 'bg-bg-tertiary text-text-muted hover:text-text-primary',
                    )}
                  >
                    {t(`infraAnalysis.filter.${f}`, { defaultValue: f })}
                  </button>
                ))}
                <input
                  value={rowSearch}
                  onChange={(e) => setRowSearch(e.target.value)}
                  placeholder={t('infraAnalysis.selection.search', { defaultValue: 'Filter by site or name' })}
                  className="ml-auto rounded-md border border-border bg-bg-tertiary px-2 py-1 text-xs text-text-primary"
                />
              </div>

              <div className="mb-3 flex flex-wrap items-center gap-2">
                <Button size="sm" variant="secondary" onClick={() => setSelected(new Set(proposals))} disabled={proposals.size === 0}>
                  {t('infraAnalysis.selectAll', { defaultValue: 'Select every proposal ({{count}})', count: proposals.size })}
                </Button>
                {siteOverwrites > 0 && (
                  <span className="text-xs text-amber-400">
                    {t('infraAnalysis.siteOverwritesHint', {
                      defaultValue: '{{count}} proposal(s) would change a value stored for the site: tick them one by one.',
                      count: siteOverwrites,
                    })}
                  </span>
                )}
                <Button size="sm" variant="ghost" onClick={() => setSelected(new Set())} disabled={selected.size === 0}>
                  {t('infraAnalysis.clearSelection', { defaultValue: 'Clear' })}
                </Button>
                <Button size="sm" onClick={() => void apply()} loading={applying} disabled={applying || selected.size === 0}>
                  {t('infraAnalysis.apply', { defaultValue: 'Apply {{count}} row(s)', count: selected.size })}
                </Button>
                <span className="mx-1 h-5 w-px bg-border" />
                <Button size="sm" variant="secondary" onClick={() => void exportFile('variables')}>
                  <Download size={14} /> {t('infraAnalysis.export.variables', { defaultValue: 'Variables CSV (Quick Setup)' })}
                </Button>
                <Button size="sm" variant="secondary" onClick={() => void exportFile('lan')}>
                  <Download size={14} /> {t('infraAnalysis.export.lan', { defaultValue: 'LAN CSV' })}
                </Button>
                <Button size="sm" variant="secondary" onClick={() => void exportFile('lanReprise')} disabled={(counts?.lanFound ?? 0) === 0}>
                  <Network size={14} /> {t('infraAnalysis.export.toLanReprise', { defaultValue: 'Send the LANs to the LAN reprise' })}
                </Button>
              </div>

              {applyResult && applyResult.refused.length > 0 && (
                <div className="mb-3 rounded-md border border-amber-500/40 bg-amber-500/10 p-3 text-xs text-amber-400">
                  <p className="font-medium">{t('infraAnalysis.refusedTitle', { defaultValue: 'Not written' })}</p>
                  <ul className="mt-1 list-disc pl-5">
                    {applyResult.refused.map((r) => {
                      const site = snapshot.devices.find((d) => d.site?.id === r.siteId)?.site;
                      return (
                        <li key={`${r.siteId}|${r.key}`}>
                          <span className="font-mono">{site?.code ?? r.siteId}</span> {r.key} —{' '}
                          {t(`infraAnalysis.refused.${r.reason}`, { defaultValue: r.reason })}
                          {r.detail ? ` (${r.detail})` : ''}
                        </li>
                      );
                    })}
                  </ul>
                </div>
              )}

              <div className="max-h-[60vh] overflow-auto rounded-md border border-border">
                <table className="w-full">
                  <thead className="sticky top-0 bg-bg-secondary">
                    <tr>
                      <th className={TH} />
                      <th className={TH}>{t('infraAnalysis.col.site', { defaultValue: 'Site' })}</th>
                      <th className={TH}>{t('infraAnalysis.col.device', { defaultValue: 'Router' })}</th>
                      <th className={TH}>{t('infraAnalysis.col.variable', { defaultValue: 'Variable' })}</th>
                      <th className={TH}>{t('infraAnalysis.col.found', { defaultValue: 'On the router' })}</th>
                      <th className={TH}>{t('infraAnalysis.col.stored', { defaultValue: 'In ObliWAN' })}</th>
                      <th className={TH}>{t('infraAnalysis.col.verdict', { defaultValue: 'Verdict' })}</th>
                    </tr>
                  </thead>
                  <tbody>
                    {rows.length === 0 && (
                      <tr>
                        <td colSpan={7} className={cn(TD, 'text-center text-text-muted')}>
                          {t('infraAnalysis.empty', { defaultValue: 'No row for this filter.' })}
                        </td>
                      </tr>
                    )}
                    {rows.map(({ device: d, variable: v }) => {
                      const siteCell = d.site ? (
                        <>
                          <span className="font-mono">{d.site.code}</span> <span className="text-text-muted">{d.site.name}</span>
                        </>
                      ) : (
                        '—'
                      );
                      if (!v) {
                        return (
                          <tr key={`d${d.deviceId}`} className="border-t border-border">
                            <td className={TD} />
                            <td className={TD}>{siteCell}</td>
                            <td className={TD}>{d.deviceName}</td>
                            <td className={cn(TD, d.state === 'failed' ? 'text-red-400' : 'text-amber-400')} colSpan={4}>
                              {t(`infraAnalysis.device.state.${d.state}`, { defaultValue: d.state })}:{' '}
                              {t(`infraAnalysis.device.reason.${d.reason ?? 'internal'}`, { defaultValue: d.reason ?? '' })}
                              {d.detail ? <span className="block text-xs text-text-muted">{d.detail}</span> : null}
                            </td>
                          </tr>
                        );
                      }
                      const k = d.site ? rowKey(d.site.id, v.key) : null;
                      const selectable = k !== null && v.action !== null && !v.appliedAt;
                      return (
                        <tr key={`d${d.deviceId}-${v.key}`} className="border-t border-border">
                          <td className={TD}>
                            {selectable && k !== null && <input type="checkbox" checked={selected.has(k)} onChange={() => toggle(k)} />}
                          </td>
                          <td className={TD}>{siteCell}</td>
                          <td className={TD}>
                            {d.deviceName}
                            {d.noRevision && (
                              <span className="block text-xs text-text-muted">
                                {t('infraAnalysis.device.noRevision', { defaultValue: 'no template assignment: only the LAN was read' })}
                              </span>
                            )}
                          </td>
                          <td className={TD}>
                            <span className="font-mono text-xs">{v.key}</span>
                            {v.label && <span className="block text-xs text-text-muted">{v.label}</span>}
                          </td>
                          <td className={cn(TD, 'font-mono text-xs')}>
                            {foundText(v.found)}
                            {v.elsewhere.length > 0 && (
                              <span className="block font-sans text-xs text-amber-400">
                                {t('infraAnalysis.elsewhere', {
                                  defaultValue: 'also: {{items}}',
                                  items: v.elsewhere
                                    .map((e) => `${e.name ?? '?'} (${Object.entries(e.values).map(([p, x]) => `${p}=${x}`).join(', ')})`)
                                    .join('; '),
                                })}
                              </span>
                            )}
                            {v.invalidReasons.length > 0 && (
                              <span className="block font-sans text-xs text-red-400">{v.invalidReasons.join('; ')}</span>
                            )}
                          </td>
                          <td className={cn(TD, 'text-xs')}>
                            {storedText(v)}
                            {v.stored.level === 'device' && (
                              <span className="block text-amber-400">
                                {t('infraAnalysis.deviceOverride', { defaultValue: 'a device value hides the site value' })}
                              </span>
                            )}
                          </td>
                          <td className={TD}>
                            <span className={cn('rounded px-1.5 py-0.5 text-xs', VERDICT_STYLE[v.verdict])}>
                              {t(`infraAnalysis.verdict.${v.verdict}`, { defaultValue: v.verdict })}
                            </span>
                            {v.action && (
                              <span className="block text-xs text-text-muted">
                                {t(`infraAnalysis.action.${v.action}`, { defaultValue: v.action })}
                              </span>
                            )}
                            {v.appliedAt && (
                              <span className="block text-xs text-emerald-400">{t('infraAnalysis.applied', { defaultValue: 'applied' })}</span>
                            )}
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>

              {lanRows.length > 0 && (
                <div className="mt-4">
                  <h3 className="mb-2 text-sm font-semibold text-text-primary">{t('infraAnalysis.lan.title', { defaultValue: 'Store LAN' })}</h3>
                  <div className="max-h-[40vh] overflow-auto rounded-md border border-border">
                    <table className="w-full">
                      <thead className="sticky top-0 bg-bg-secondary">
                        <tr>
                          <th className={TH}>{t('infraAnalysis.col.site', { defaultValue: 'Site' })}</th>
                          <th className={TH}>{t('infraAnalysis.lan.col.interface', { defaultValue: 'Interface' })}</th>
                          <th className={TH}>{t('infraAnalysis.lan.col.lan', { defaultValue: 'LAN' })}</th>
                          <th className={TH}>{t('infraAnalysis.lan.col.router', { defaultValue: 'Router address' })}</th>
                          <th className={TH}>{t('infraAnalysis.col.verdict', { defaultValue: 'Verdict' })}</th>
                        </tr>
                      </thead>
                      <tbody>
                        {lanRows.map((d) => (
                          <tr key={`lan${d.deviceId}`} className="border-t border-border">
                            <td className={TD}>
                              <span className="font-mono">{d.site?.code ?? '—'}</span> <span className="text-text-muted">{d.deviceName}</span>
                            </td>
                            <td className={cn(TD, 'font-mono text-xs')}>{d.lan?.interface ?? '—'}</td>
                            <td className={cn(TD, 'font-mono text-xs')}>{d.lan?.lan ?? '—'}</td>
                            <td className={cn(TD, 'font-mono text-xs')}>{d.lan?.routerIp ?? '—'}</td>
                            <td className={cn(TD, 'text-xs')}>
                              {t(`infraAnalysis.lan.status.${d.lan?.status ?? 'unreadable'}`, { defaultValue: d.lan?.status ?? '' })}
                              {d.lan && d.lan.candidates.length > 0 && (
                                <span className="block font-mono text-text-muted">
                                  {d.lan.candidates.map((c) => `${c.interface} ${c.address}`).join('; ')}
                                </span>
                              )}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}
            </>
          )}
        </div>
      )}

      {lanCsv !== null && currentTenantId !== null && (
        <LanRepriseModal
          tenantId={currentTenantId}
          tenantLabel={tenantName ?? undefined}
          initialCsv={lanCsv}
          onClose={() => setLanCsv(null)}
          onApplied={() => undefined}
        />
      )}
    </div>
  );
}
