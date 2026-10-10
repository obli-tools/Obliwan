import { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Building2, Plus, Pencil, Trash2, Users, X, Check } from 'lucide-react';
import type { Tenant, TenantRole } from '@obliwan/shared';
import { Button } from '@/components/common/Button';
import { useTenantRoleOptions, roleOptionLabel, roleOptionHint } from '@/components/users/tenantRoleOptions';

interface TenantMember {
  id: number;
  username: string;
  display_name: string | null;
  role: string;
  is_active: boolean;
  /** `user_tenants.role` as stored — a permission-set slug (migration 084,
   *  foreign key), typed as a string because it arrives over the wire. */
  tenantRole: string;
  /** Teams OF THIS TENANT the member belongs to (migration 087). Since a tenant
   *  admin sees what its teams cover, 0 means it sees nothing. Absent on an older server. */
  teamCount?: number;
}

interface TenantWithMemberCount extends Tenant {
  memberCount?: number;
}

// ── Inline form for creating / editing a tenant ────────────────────────────
function TenantForm({
  initial,
  onSave,
  onCancel,
}: {
  initial?: { name: string; slug: string };
  onSave: (name: string, slug: string) => Promise<void>;
  onCancel: () => void;
}) {
  const { t } = useTranslation();
  const [name, setName] = useState(initial?.name ?? '');
  const [slug, setSlug] = useState(initial?.slug ?? '');
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState('');

  const autoSlug = (n: string) =>
    n.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '');

  const handleNameChange = (v: string) => {
    setName(v);
    if (!initial) setSlug(autoSlug(v));
  };

  const handleSubmit = async () => {
    if (!name.trim() || !slug.trim()) { setError(t('common.requiredField')); return; }
    setSaving(true);
    setError('');
    try {
      await onSave(name.trim(), slug.trim());
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : t('common.error'));
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="flex items-end gap-2">
      <div className="flex-1">
        <label className="block text-xs text-text-muted mb-1">{t('tenant.name')}</label>
        <input
          type="text"
          value={name}
          onChange={(e) => handleNameChange(e.target.value)}
          className="w-full rounded-lg border border-border bg-bg-primary px-3 py-1.5 text-sm text-text-primary focus:outline-none focus:ring-1 focus:ring-accent"
          placeholder={t('tenant.namePlaceholder')}
        />
      </div>
      <div className="w-40">
        <label className="block text-xs text-text-muted mb-1">{t('tenant.slug')}</label>
        <input
          type="text"
          value={slug}
          onChange={(e) => setSlug(e.target.value)}
          className="w-full rounded-lg border border-border bg-bg-primary px-3 py-1.5 text-sm text-text-primary focus:outline-none focus:ring-1 focus:ring-accent"
          placeholder="my-org"
        />
      </div>
      {error && <p className="text-xs text-red-400">{error}</p>}
      <Button size="sm" onClick={handleSubmit} disabled={saving}>
        <Check size={14} />
      </Button>
      <Button size="sm" variant="ghost" onClick={onCancel} disabled={saving}>
        <X size={14} />
      </Button>
    </div>
  );
}

// ── Members panel ───────────────────────────────────────────────────────────
function MembersPanel({ tenantId, onClose }: { tenantId: number; onClose: () => void }) {
  const { t } = useTranslation();
  const [members, setMembers] = useState<TenantMember[]>([]);
  const [allUsers, setAllUsers] = useState<{ id: number; username: string }[]>([]);
  const [loading, setLoading] = useState(true);
  const [addingId, setAddingId] = useState<number | ''>('');
  // Chosen BEFORE the add, so an account manager is never a member — with
  // configuration snapshots and device writes — for the moment between the
  // add and a role change.
  const [addingRole, setAddingRole] = useState<TenantRole>('user');
  // Builtin roles + custom permission sets (a role IS a set since 084).
  const roleOptions = useTenantRoleOptions();
  const isKnownRole = (v: string) => roleOptions.some((o) => o.role === v);

  const fetchMembers = async () => {
    const res = await fetch(`/api/tenants/${tenantId}/members`, { credentials: 'include' });
    const d = await res.json();
    setMembers(d.data ?? []);
    setLoading(false);
  };

  const fetchUsers = async () => {
    const res = await fetch('/api/users', { credentials: 'include' });
    const d = await res.json();
    setAllUsers(d.data ?? []);
  };

  useEffect(() => {
    fetchMembers();
    fetchUsers();
  }, [tenantId]);

  const addMember = async () => {
    if (!addingId) return;
    await fetch(`/api/tenants/${tenantId}/members`, {
      method: 'POST',
      credentials: 'include',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ userId: addingId, role: addingRole }),
    });
    setAddingId('');
    setAddingRole('user');
    fetchMembers();
  };

  // An explicit pick among the roles. This used to be a toggle that
  // sent `currentRole === 'admin' ? 'member' : 'admin'`, which read an account
  // manager as "not admin" and made her a tenant admin — secrets, change and
  // top-up approval — in one click on her badge.
  const setRole = async (userId: number, newRole: TenantRole) => {
    await fetch(`/api/tenants/${tenantId}/members/${userId}`, {
      method: 'PUT',
      credentials: 'include',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ role: newRole }),
    });
    fetchMembers();
  };

  const removeMember = async (userId: number) => {
    if (!confirm(t('common.confirmDelete'))) return;
    await fetch(`/api/tenants/${tenantId}/members/${userId}`, {
      method: 'DELETE',
      credentials: 'include',
    });
    fetchMembers();
  };

  const nonMembers = allUsers.filter((u) => !members.find((m) => m.id === u.id));

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60">
      <div className="w-full max-w-lg rounded-2xl border border-border bg-bg-secondary shadow-2xl">
        <div className="flex items-center justify-between px-5 py-4 border-b border-border">
          <h3 className="text-sm font-semibold text-text-primary flex items-center gap-2">
            <Users size={15} />
            {t('tenant.members')}
          </h3>
          <button onClick={onClose} className="text-text-muted hover:text-text-primary">
            <X size={16} />
          </button>
        </div>

        <div className="px-5 py-4 space-y-3 max-h-80 overflow-y-auto">
          {loading ? (
            <p className="text-sm text-text-muted text-center py-4">{t('common.loading')}</p>
          ) : members.length === 0 ? (
            <p className="text-sm text-text-muted text-center py-4">{t('tenant.noMembers')}</p>
          ) : (
            members.map((m) => (
              <div key={m.id} className="flex items-center justify-between gap-2">
                <div className="min-w-0">
                  <span className="text-sm text-text-primary font-medium">{m.username}</span>
                  {m.display_name && (
                    <span className="ml-1 text-xs text-text-muted">({m.display_name})</span>
                  )}
                </div>
                <div className="flex items-center gap-2 shrink-0">
                  {/* A platform admin (users.role = admin) sees the whole workspace
                      without a team; every other member sees what its teams cover. */}
                  {m.role !== 'admin' && m.teamCount === 0 && (
                    <span
                      className="text-[10px] px-1.5 py-0.5 rounded-full border border-status-warn/40 bg-status-warn/10 text-status-warn"
                      title={t('teamScope.noTeamBanner')}
                    >
                      {t('users.tenantRole.noTeam')}
                    </span>
                  )}
                  <select
                    value={m.tenantRole}
                    onChange={(e) => {
                      if (isKnownRole(e.target.value)) void setRole(m.id, e.target.value);
                    }}
                    aria-label={t('users.tenantRole.label', 'Role')}
                    title={(() => {
                      const opt = roleOptions.find((o) => o.role === m.tenantRole);
                      return opt ? roleOptionHint(t, opt) : undefined;
                    })()}
                    className={`text-xs px-2 py-0.5 rounded-full border bg-bg-primary transition-colors focus:outline-none focus:ring-1 focus:ring-accent ${
                      m.tenantRole === 'admin'
                        ? 'border-accent text-accent'
                        : 'border-border text-text-muted'
                    }`}
                  >
                    {/* A stored value the client does not know is shown as is,
                        never silently displayed as one of the known roles. */}
                    {!isKnownRole(m.tenantRole) && (
                      <option value={m.tenantRole} disabled>{m.tenantRole}</option>
                    )}
                    {roleOptions.map((opt) => (
                      <option key={opt.role} value={opt.role}>{roleOptionLabel(t, opt)}</option>
                    ))}
                  </select>
                  <button
                    onClick={() => removeMember(m.id)}
                    className="text-text-muted hover:text-red-400 transition-colors"
                    title={t('tenant.removeMember')}
                  >
                    <X size={13} />
                  </button>
                </div>
              </div>
            ))
          )}
        </div>

        {nonMembers.length > 0 && (
          <div className="px-5 py-3 border-t border-border flex items-center gap-2">
            <select
              value={addingId}
              onChange={(e) => setAddingId(e.target.value ? Number(e.target.value) : '')}
              className="flex-1 rounded-lg border border-border bg-bg-primary px-3 py-1.5 text-sm text-text-primary focus:outline-none focus:ring-1 focus:ring-accent"
            >
              <option value="">{t('tenant.selectUser')}</option>
              {nonMembers.map((u) => (
                <option key={u.id} value={u.id}>{u.username}</option>
              ))}
            </select>
            <select
              value={addingRole}
              onChange={(e) => {
                if (isKnownRole(e.target.value)) setAddingRole(e.target.value);
              }}
              aria-label={t('users.tenantRole.label', 'Role')}
              className="rounded-lg border border-border bg-bg-primary px-2 py-1.5 text-sm text-text-primary focus:outline-none focus:ring-1 focus:ring-accent"
            >
              {roleOptions.map((opt) => (
                <option key={opt.role} value={opt.role}>{roleOptionLabel(t, opt)}</option>
              ))}
            </select>
            <Button size="sm" onClick={addMember} disabled={!addingId}>
              {t('tenant.addMember')}
            </Button>
          </div>
        )}
      </div>
    </div>
  );
}

// ── Main page ───────────────────────────────────────────────────────────────
export function AdminTenantsPage() {
  const { t } = useTranslation();
  const [tenants, setTenants] = useState<TenantWithMemberCount[]>([]);
  const [loading, setLoading] = useState(true);
  const [creating, setCreating] = useState(false);
  const [editingId, setEditingId] = useState<number | null>(null);
  const [membersForId, setMembersForId] = useState<number | null>(null);

  const fetchTenants = async () => {
    setLoading(true);
    try {
      const res = await fetch('/api/tenants', { credentials: 'include' });
      const d = await res.json();
      setTenants(d.data ?? []);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { fetchTenants(); }, []);

  const handleCreate = async (name: string, slug: string) => {
    const res = await fetch('/api/tenants', {
      method: 'POST',
      credentials: 'include',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name, slug }),
    });
    if (!res.ok) {
      const d = await res.json();
      throw new Error(d.error ?? t('common.error'));
    }
    setCreating(false);
    fetchTenants();
  };

  const handleUpdate = async (id: number, name: string, slug: string) => {
    const res = await fetch(`/api/tenants/${id}`, {
      method: 'PUT',
      credentials: 'include',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name, slug }),
    });
    if (!res.ok) {
      const d = await res.json();
      throw new Error(d.error ?? t('common.error'));
    }
    setEditingId(null);
    fetchTenants();
  };

  const handleDelete = async (id: number) => {
    if (!confirm(t('tenant.confirmDelete'))) return;
    await fetch(`/api/tenants/${id}`, { method: 'DELETE', credentials: 'include' });
    fetchTenants();
  };

  return (
    <div className="p-6">
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-xl font-bold text-text-primary flex items-center gap-2">
            <Building2 size={20} className="text-accent" />
            {t('tenant.pageTitle')}
          </h1>
          <p className="text-sm text-text-muted mt-0.5">{t('tenant.pageDesc')}</p>
        </div>
        {!creating && (
          <Button size="sm" onClick={() => setCreating(true)}>
            <Plus size={14} />
            {t('tenant.create')}
          </Button>
        )}
      </div>

      {creating && (
        <div className="mb-4 p-4 rounded-xl border border-border bg-bg-secondary">
          <TenantForm onSave={handleCreate} onCancel={() => setCreating(false)} />
        </div>
      )}

      {loading ? (
        <p className="text-sm text-text-muted">{t('common.loading')}</p>
      ) : tenants.length === 0 ? (
        <p className="text-sm text-text-muted">{t('tenant.noTenants')}</p>
      ) : (
        <div className="space-y-2">
          {tenants.map((tenant) => (
            <div
              key={tenant.id}
              className="rounded-xl border border-border bg-bg-secondary px-4 py-3"
            >
              {editingId === tenant.id ? (
                <TenantForm
                  initial={{ name: tenant.name, slug: tenant.slug }}
                  onSave={(name, slug) => handleUpdate(tenant.id, name, slug)}
                  onCancel={() => setEditingId(null)}
                />
              ) : (
                <div className="flex items-center justify-between gap-3">
                  <div className="min-w-0">
                    <div className="flex items-center gap-2">
                      <Building2 size={14} className="text-accent shrink-0" />
                      <span className="text-sm font-semibold text-text-primary">{tenant.name}</span>
                      {tenant.id === 1 && (
                        <span className="text-[10px] bg-accent/15 text-accent rounded px-1.5 py-0.5">
                          {t('tenant.default')}
                        </span>
                      )}
                    </div>
                    <p className="text-xs text-text-muted mt-0.5">
                      /{tenant.slug} · {t('tenant.createdAt')} {new Date(tenant.createdAt).toLocaleDateString()}
                    </p>
                  </div>
                  <div className="flex items-center gap-1 shrink-0">
                    <button
                      onClick={() => setMembersForId(tenant.id)}
                      title={t('tenant.manageMembers')}
                      className="flex items-center gap-1 text-xs text-text-muted hover:text-text-primary px-2 py-1 rounded-md hover:bg-bg-hover transition-colors"
                    >
                      <Users size={13} />
                      {t('tenant.members')}
                    </button>
                    <button
                      onClick={() => setEditingId(tenant.id)}
                      title={t('common.edit')}
                      className="p-1.5 text-text-muted hover:text-text-primary rounded-md hover:bg-bg-hover transition-colors"
                    >
                      <Pencil size={13} />
                    </button>
                    {tenant.id !== 1 && (
                      <button
                        onClick={() => handleDelete(tenant.id)}
                        title={t('common.delete')}
                        className="p-1.5 text-text-muted hover:text-red-400 rounded-md hover:bg-bg-hover transition-colors"
                      >
                        <Trash2 size={13} />
                      </button>
                    )}
                  </div>
                </div>
              )}
            </div>
          ))}
        </div>
      )}

      {membersForId !== null && (
        <MembersPanel tenantId={membersForId} onClose={() => setMembersForId(null)} />
      )}
    </div>
  );
}
