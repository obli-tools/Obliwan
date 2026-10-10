import { useState, useEffect, useCallback, useMemo } from 'react';
import { Plus, Trash2, Check, Shield, Pencil, X, Lock, RotateCcw, AlertTriangle } from 'lucide-react';
import { CAPABILITY_DOMAINS, expandCapabilities, isCapability } from '@obliwan/shared';
import type { PermissionSet } from '@obliwan/shared';
import { Button } from '@/components/common/Button';
import { Input } from '@/components/common/Input';
import { permissionSetsApi, apiErrorMessage, type CapabilityMatrixInfo } from '@/api/permissionSets.api';
import toast from 'react-hot-toast';
import { useTranslation } from 'react-i18next';

/**
 * The permission-set matrix — AUTHORITATIVE since migration 084.
 *
 * A set IS a tenant role (`user_tenants.role` is its slug) and the server
 * grants what its row lists, at the next request, for EVERY holder in EVERY
 * workspace: the four builtin roles are shared by all tenants, like Obliance's.
 * So the screen says, per column, how many memberships a tick reaches; shows
 * what a tick brings with it (implied capabilities, greyed); locks what no set
 * may carry (platform-only, and credential.manage which is granted by name);
 * and asks for a confirmation before an explicit-only grant (money, secrets in
 * clear, the second pair of eyes). Every write is audited server-side.
 */
export function PermissionSetsTab() {
  const { t } = useTranslation();

  const [sets, setSets] = useState<PermissionSet[]>([]);
  const [capabilities, setCapabilities] = useState<CapabilityMatrixInfo[]>([]);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);

  const [showCreate, setShowCreate] = useState(false);
  const [newName, setNewName] = useState('');
  const [creating, setCreating] = useState(false);

  const [renamingId, setRenamingId] = useState<number | null>(null);
  const [renameValue, setRenameValue] = useState('');

  const fetchData = useCallback(async () => {
    try {
      const [s, c] = await Promise.all([permissionSetsApi.list(), permissionSetsApi.capabilities()]);
      setSets(s);
      setCapabilities(c);
    } catch {
      toast.error(t('permissionSets.loadFailed', 'Failed to load permission sets'));
    } finally {
      setLoading(false);
    }
  }, [t]);

  useEffect(() => { void fetchData(); }, [fetchData]);

  const byKey = useMemo(() => new Map(capabilities.map((c) => [c.key as string, c])), [capabilities]);

  /** For a set: capability → the ticked capability that implies it (first found). */
  const impliedBy = useCallback((set: PermissionSet): Map<string, string> => {
    const out = new Map<string, string>();
    const held = set.capabilities.filter(isCapability);
    for (const c of held) {
      for (const x of expandCapabilities([c])) {
        if (x !== c && !held.includes(x) && !out.has(x)) out.set(x, c);
      }
    }
    return out;
  }, []);

  const save = async (set: PermissionSet, next: string[]) => {
    setBusy(true);
    setSets((prev) => prev.map((s) => (s.id === set.id ? { ...s, capabilities: next } : s)));
    try {
      await permissionSetsApi.update(set.id, { capabilities: next });
    } catch (err) {
      toast.error(apiErrorMessage(err) ?? t('permissionSets.updateFailed', 'Failed to update permission set'));
      void fetchData();
    } finally {
      setBusy(false);
    }
  };

  const toggleCapability = async (set: PermissionSet, cap: CapabilityMatrixInfo) => {
    if (cap.lock) return;
    const has = set.capabilities.includes(cap.key);
    if (!has) {
      const reach = set.memberCount ?? 0;
      if (cap.explicitOnly) {
        const ok = confirm(
          t(`permissionSets.confirmExplicit.${cap.key.replace('.', '_')}`, {
            defaultValue: t('permissionSets.confirmExplicitGeneric', {
              cap: cap.label,
              set: set.name,
              defaultValue: 'Grant "{{cap}}" to every holder of "{{set}}"?',
            }),
            set: set.name,
            count: reach,
          }),
        );
        if (!ok) return;
      } else if (cap.sensitive && reach > 0) {
        const ok = confirm(t('permissionSets.confirmSensitive', {
          cap: cap.label, set: set.name, count: reach,
          defaultValue: 'Grant "{{cap}}" to the {{count}} membership(s) holding "{{set}}"?',
        }));
        if (!ok) return;
      }
    }
    const next = has ? set.capabilities.filter((c) => c !== cap.key) : [...set.capabilities, cap.key];
    await save(set, next);
  };

  const handleCreate = async () => {
    if (!newName.trim()) return;
    setCreating(true);
    try {
      await permissionSetsApi.create({ name: newName.trim(), capabilities: [] });
      toast.success(t('permissionSets.created', 'Permission set created'));
      setNewName('');
      setShowCreate(false);
      void fetchData();
    } catch (err) {
      toast.error(apiErrorMessage(err) ?? t('permissionSets.createFailed', 'Failed to create permission set'));
    } finally {
      setCreating(false);
    }
  };

  const handleDelete = async (set: PermissionSet) => {
    if (!confirm(t('permissionSets.confirmDelete', { name: set.name, defaultValue: 'Delete permission set "{{name}}"? This cannot be undone.' }))) return;
    try {
      await permissionSetsApi.remove(set.id);
      toast.success(t('permissionSets.deleted', 'Permission set deleted'));
      void fetchData();
    } catch (err) {
      toast.error(apiErrorMessage(err) ?? t('permissionSets.deleteFailed', 'Failed to delete permission set'));
    }
  };

  const handleReset = async (set: PermissionSet) => {
    if (!confirm(t('permissionSets.confirmReset', { name: set.name, defaultValue: 'Reset "{{name}}" to its default capabilities?' }))) return;
    try {
      await permissionSetsApi.reset(set.id);
      toast.success(t('permissionSets.resetDone', 'Role reset to its defaults'));
      void fetchData();
    } catch (err) {
      toast.error(apiErrorMessage(err) ?? t('permissionSets.updateFailed', 'Failed to update permission set'));
    }
  };

  const handleRename = async (set: PermissionSet) => {
    if (!renameValue.trim() || renameValue.trim() === set.name) {
      setRenamingId(null);
      return;
    }
    try {
      await permissionSetsApi.update(set.id, { name: renameValue.trim() });
      toast.success(t('permissionSets.renamed', 'Permission set renamed'));
      setRenamingId(null);
      void fetchData();
    } catch (err) {
      toast.error(apiErrorMessage(err) ?? t('permissionSets.updateFailed', 'Failed to update permission set'));
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center py-12 text-text-muted text-sm">
        {t('common.loading', 'Loading…')}
      </div>
    );
  }

  const lockTitle = (c: CapabilityMatrixInfo) =>
    c.lock === 'platform_only'
      ? t('permissionSets.lockPlatform', 'Platform administrators only — never in a role')
      : t('permissionSets.lockByName', 'Granted by name only (team grant or Obligate) — never by a role');

  return (
    <div>
      <div className="flex items-center justify-between mb-2">
        <h2 className="text-lg font-semibold text-text-primary">
          {t('users.permissionSets', 'Permission Sets')}
        </h2>
        <Button size="sm" onClick={() => setShowCreate(true)}>
          <Plus size={14} className="mr-1" />
          {t('common.new', 'New')}
        </Button>
      </div>
      <div className="mb-4 flex items-start gap-2 rounded-lg border border-amber-500/30 bg-amber-500/5 p-3 text-xs text-text-secondary">
        <AlertTriangle size={14} className="text-amber-500 mt-0.5 shrink-0" />
        <p>
          {t(
            'permissionSets.authoritativeNotice',
            'Each column is a workspace role. A tick is a grant, at once, to every member holding that role in every workspace — and every change is audited. WHAT a role may do is decided here; WHERE is decided by the user\'s teams.',
          )}
        </p>
      </div>

      {showCreate && (
        <div className="mb-4 rounded-lg border border-border bg-bg-secondary p-4">
          <h3 className="text-sm font-semibold text-text-secondary uppercase tracking-wide mb-3">
            {t('permissionSets.newTitle', 'New permission set')}
          </h3>
          <div className="flex items-center gap-2">
            <Input
              value={newName}
              onChange={(e) => setNewName(e.target.value)}
              placeholder={t('permissionSets.namePlaceholder')}
              onKeyDown={(e) => { if (e.key === 'Enter') void handleCreate(); }}
              autoFocus
            />
            <Button size="sm" onClick={() => void handleCreate()} disabled={creating || !newName.trim()}>
              {creating ? '…' : t('common.create', 'Create')}
            </Button>
            <button
              onClick={() => { setShowCreate(false); setNewName(''); }}
              className="p-1 text-text-muted hover:text-text-primary"
            >
              <X size={16} />
            </button>
          </div>
        </div>
      )}

      {capabilities.length === 0 ? (
        <div className="text-sm text-text-muted py-8 text-center">
          {t('permissionSets.noCapabilities', 'No capabilities defined.')}
        </div>
      ) : (
        <div className="overflow-x-auto rounded-lg border border-border">
          <table className="w-full text-sm">
            <thead>
              <tr className="bg-bg-secondary border-b border-border">
                <th className="text-left px-3 py-2.5 text-text-secondary font-medium whitespace-nowrap">
                  {t('permissionSets.capability', 'Capability')}
                </th>
                {sets.map((set) => (
                  <th key={set.id} className="px-3 py-2.5 text-center min-w-[110px] align-top">
                    <div className="flex items-center justify-center gap-1">
                      {renamingId === set.id ? (
                        <input
                          className="bg-bg-tertiary border border-border rounded px-1.5 py-0.5 text-xs text-text-primary w-24 text-center"
                          value={renameValue}
                          onChange={(e) => setRenameValue(e.target.value)}
                          onBlur={() => void handleRename(set)}
                          onKeyDown={(e) => {
                            if (e.key === 'Enter') void handleRename(set);
                            if (e.key === 'Escape') setRenamingId(null);
                          }}
                          autoFocus
                        />
                      ) : (
                        <>
                          <span className="text-text-primary font-medium text-xs" title={set.description ?? undefined}>
                            {set.name}
                          </span>
                          {set.isDefault && (
                            <span title={t('permissionSets.defaultSet')}><Shield size={11} className="text-accent shrink-0" /></span>
                          )}
                        </>
                      )}
                    </div>
                    <div className="text-[10px] text-text-muted font-mono">{set.slug}</div>
                    <div className="text-[10px] text-text-muted" title={t('permissionSets.reachHint', 'Memberships holding this role, across every workspace')}>
                      {t('permissionSets.reach', {
                        count: set.memberCount ?? 0,
                        tenants: set.tenantCount ?? 0,
                        defaultValue: '{{count}} member(s) · {{tenants}} workspace(s)',
                      })}
                    </div>
                    {renamingId !== set.id && (
                      <div className="flex items-center justify-center gap-0.5 mt-1">
                        <button
                          onClick={() => { setRenamingId(set.id); setRenameValue(set.name); }}
                          className="p-0.5 text-text-muted hover:text-text-primary opacity-60 hover:opacity-100"
                          title={t('permissionSets.rename', 'Rename')}
                        >
                          <Pencil size={10} />
                        </button>
                        {set.isDefault ? (
                          <button
                            onClick={() => void handleReset(set)}
                            className="p-0.5 text-text-muted hover:text-text-primary opacity-60 hover:opacity-100"
                            title={t('permissionSets.reset', 'Reset to defaults')}
                          >
                            <RotateCcw size={10} />
                          </button>
                        ) : (
                          <button
                            onClick={() => void handleDelete(set)}
                            className="p-0.5 text-text-muted hover:text-status-down opacity-60 hover:opacity-100"
                            title={t('permissionSets.delete', 'Delete')}
                          >
                            <Trash2 size={10} />
                          </button>
                        )}
                      </div>
                    )}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {CAPABILITY_DOMAINS.map((domain) => {
                const rows = capabilities.filter((c) => c.domain === domain);
                if (rows.length === 0) return null;
                return [
                  <tr key={`d-${domain}`} className="bg-bg-tertiary/60 border-b border-border">
                    <td colSpan={sets.length + 1} className="px-3 py-1 text-[10px] uppercase tracking-wide text-text-muted font-semibold">
                      {t(`permissionSets.domain.${domain}`, domain)}
                    </td>
                  </tr>,
                  ...rows.map((cap) => (
                    <tr key={cap.key} className="border-b border-border last:border-b-0 hover:bg-bg-hover transition-colors">
                      <td className="px-3 py-2 text-text-primary text-xs" title={cap.description}>
                        <div className="flex items-center gap-1.5">
                          <span className="font-medium whitespace-nowrap">{cap.label}</span>
                          {cap.sensitive && (
                            <span className="text-[9px] px-1 rounded bg-status-down/10 text-status-down">{t('permissionSets.sensitive', 'sensitive')}</span>
                          )}
                          {cap.explicitOnly && (
                            <span className="text-[9px] px-1 rounded bg-amber-500/10 text-amber-500" title={t('permissionSets.explicitHint', 'Never implied by another capability: only an explicit tick grants it')}>
                              {t('permissionSets.explicit', 'explicit')}
                            </span>
                          )}
                        </div>
                        <div className="text-[10px] text-text-muted font-mono">{cap.key}</div>
                      </td>
                      {sets.map((set) => {
                        const checked = set.capabilities.includes(cap.key);
                        const via = impliedBy(set).get(cap.key);
                        if (cap.lock) {
                          return (
                            <td key={set.id} className="px-3 py-2 text-center" title={lockTitle(cap)}>
                              <Lock size={12} className="inline text-text-muted opacity-60" />
                            </td>
                          );
                        }
                        return (
                          <td key={set.id} className="px-3 py-2 text-center">
                            <button
                              disabled={busy}
                              onClick={() => void toggleCapability(set, cap)}
                              title={!checked && via
                                ? t('permissionSets.impliedBy', { cap: byKey.get(via)?.label ?? via, defaultValue: 'Implied by "{{cap}}"' })
                                : undefined}
                              className={`w-5 h-5 rounded border inline-flex items-center justify-center transition-colors ${
                                checked
                                  ? 'bg-accent border-accent text-white'
                                  : via
                                    ? 'bg-accent/20 border-accent/30 text-accent'
                                    : 'border-border bg-bg-tertiary hover:border-text-muted'
                              }`}
                            >
                              {(checked || via) && <Check size={12} strokeWidth={3} />}
                            </button>
                          </td>
                        );
                      })}
                    </tr>
                  )),
                ];
              })}
            </tbody>
          </table>
        </div>
      )}

      {sets.length === 0 && capabilities.length > 0 && (
        <div className="text-sm text-text-muted py-8 text-center">
          {t('permissionSets.none', 'No permission sets defined. Click "New" to create one.')}
        </div>
      )}
    </div>
  );
}
