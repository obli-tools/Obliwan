import { POLICY_FILE_FORMAT, type SetupPolicyFile } from '@obliwan/shared';
import type { AddressPool, AllocationPolicy, ConcentratorOption } from '@/api/allocation.api';

/**
 * The allocation rule as the Quick Setup form holds it, and the two
 * conversions it needs: from what is stored or from a file, and back to the
 * file shape (`obliwan-allocation-policy/1`) the API reads.
 *
 * Pools and the concentrator are held BY NAME — the portable reference an
 * export writes, so a file made on one installation reads on another. An id
 * is kept only when a file gave one: then it is sent beside the name, so the
 * server can say the two disagree (`POLICY_REF` mismatch) rather than this
 * screen picking one of them silently.
 */

export interface NamedRef {
  /** '' = none chosen. */
  name: string;
  /** Only from a file that carried an id; cleared by any choice in the form. */
  id: number | null;
}

export interface DerivedRow {
  id: string;
  key: string;
  expr: string;
}

export interface PolicyDraft {
  tunnelPool: NamedRef;
  tunnelMode: 'incremental' | 'formula';
  tunnelStart: string;
  tunnelFormula: string;
  lanMode: '' | 'incremental' | 'formula' | 'fixed' | 'manual';
  lanPool: NamedRef;
  lanPrefix: string;
  lanFormula: string;
  lanSubnet: string;
  lanVariable: string;
  login: string;
  identity: string;
  passwordMode: 'shared' | 'per_site';
  profile: string;
  concentrator: NamedRef;
  /** '' = the key is absent: the stored format is kept. Else 'free' | 'digits:N'. */
  codeFormat: string;
  derived: DerivedRow[];
}

/** The derived values a rule may carry (the allocation validator's cap). */
export const MAX_DERIVED = 20;

let seq = 0;
export function newId(prefix: string): string {
  seq += 1;
  return `${prefix}${Date.now().toString(36)}${seq}`;
}

export const EMPTY_POLICY: PolicyDraft = {
  tunnelPool: { name: '', id: null },
  tunnelMode: 'formula',
  tunnelStart: '',
  tunnelFormula: '',
  lanMode: '',
  lanPool: { name: '', id: null },
  lanPrefix: '24',
  lanFormula: '',
  lanSubnet: '',
  lanVariable: 'lan_subnet',
  login: '',
  identity: '',
  passwordMode: 'shared',
  profile: '',
  concentrator: { name: '', id: null },
  codeFormat: '',
  derived: [],
};

export type StoredPolicy = AllocationPolicy & { concentratorName?: string | null };

function derivedRows(d: Record<string, string> | null | undefined): DerivedRow[] {
  return Object.entries(d ?? {}).map(([key, expr]) => ({ id: newId('d'), key, expr: String(expr) }));
}

/** The stored rule, as the form starts from it. The code format starts on
 *  "keep the current one": re-sending the stored value would change nothing,
 *  and leaving the key out says so explicitly. */
export function policyDraftFromStored(p: StoredPolicy): PolicyDraft {
  return {
    tunnelPool: { name: p.tunnel.poolName ?? '', id: p.tunnel.poolName ? null : p.tunnel.poolId },
    tunnelMode: p.tunnel.mode,
    tunnelStart: p.tunnel.start ?? '',
    tunnelFormula: p.tunnel.formula ?? '',
    lanMode: p.lan?.mode ?? '',
    lanPool: { name: p.lan?.poolName ?? '', id: p.lan?.poolName ? null : p.lan?.poolId ?? null },
    lanPrefix: p.lan?.prefix ? String(p.lan.prefix) : '24',
    lanFormula: p.lan?.formula ?? '',
    lanSubnet: p.lan?.subnet ?? '',
    lanVariable: p.lan?.variable ?? 'lan_subnet',
    login: p.pppLoginTemplate,
    identity: p.systemIdentityTemplate ?? '',
    passwordMode: p.pppPasswordMode,
    profile: p.pppProfile ?? '',
    concentrator: { name: p.concentratorName ?? '', id: p.concentratorName ? null : p.concentratorId },
    codeFormat: '',
    derived: derivedRows(p.derived),
  };
}

function refFrom(name: unknown, id: unknown, byId: (id: number) => string | undefined): NamedRef {
  const n = typeof name === 'string' ? name : '';
  const i = typeof id === 'number' && Number.isInteger(id) ? id : null;
  if (n !== '') return { name: n, id: i };
  if (i !== null) {
    const known = byId(i);
    return known !== undefined ? { name: known, id: null } : { name: '', id: i };
  }
  return { name: '', id: null };
}

function str(v: unknown): string {
  return typeof v === 'string' ? v : typeof v === 'number' ? String(v) : '';
}

/** A rule file (or a bundle's rule), as the form holds it. Unknown members are
 *  not kept: the form cannot show them, and the server judges the file the
 *  form sends, not the one that was dropped. */
export function policyDraftFromFile(
  file: Partial<SetupPolicyFile> & Record<string, unknown>,
  pools: AddressPool[],
  concentrators: ConcentratorOption[],
): PolicyDraft {
  const poolName = (id: number) => pools.find((p) => p.id === id)?.name;
  const chrName = (id: number) => concentrators.find((c) => c.id === id)?.name;
  const tunnel = (file.tunnel ?? {}) as Record<string, unknown>;
  const lan = (file.lan ?? null) as Record<string, unknown> | null;
  const lanMode = lan && typeof lan.mode === 'string' ? lan.mode : '';
  return {
    tunnelPool: refFrom(tunnel.poolName, tunnel.poolId, poolName),
    tunnelMode: tunnel.mode === 'incremental' ? 'incremental' : 'formula',
    tunnelStart: str(tunnel.start),
    tunnelFormula: str(tunnel.formula),
    lanMode: (['incremental', 'formula', 'fixed', 'manual'] as const).find((m) => m === lanMode) ?? '',
    lanPool: lan ? refFrom(lan.poolName, lan.poolId, poolName) : { name: '', id: null },
    lanPrefix: lan && lan.prefix !== undefined ? str(lan.prefix) : '24',
    lanFormula: lan ? str(lan.formula) : '',
    lanSubnet: lan ? str(lan.subnet) : '',
    lanVariable: lan && typeof lan.variable === 'string' ? lan.variable : 'lan_subnet',
    login: str(file.pppLoginTemplate),
    identity: str(file.systemIdentityTemplate),
    passwordMode: file.pppPasswordMode === 'per_site' ? 'per_site' : 'shared',
    profile: str(file.pppProfile),
    concentrator: refFrom(file.concentratorName, file.concentratorId, chrName),
    codeFormat: typeof file.siteCodeFormat === 'string' ? file.siteCodeFormat : '',
    derived:
      file.derived && typeof file.derived === 'object'
        ? derivedRows(file.derived as Record<string, string>)
        : [],
  };
}

function poolRef(ref: NamedRef): { poolName?: string; poolId?: number } {
  if (ref.name !== '') return ref.id !== null ? { poolName: ref.name, poolId: ref.id } : { poolName: ref.name };
  return ref.id !== null ? { poolId: ref.id } : {};
}

/** A whole number typed in a field, or undefined. Trimmed first: `Number('')`
 *  and `Number(' ')` are both 0, and a blank prefix must not become /0. */
function intOf(text: string): number | undefined {
  const s = text.trim();
  if (!/^[+-]?\d{1,9}$/.test(s)) return s === '' ? undefined : Number.NaN;
  return Number(s);
}

/** The form, as the API's rule file. What the server cannot accept (an empty
 *  pool, a prefix that is not a number) is sent as it is and refused there,
 *  by field: the server's validator is the verdict, not this function. */
export function policyFileFromDraft(d: PolicyDraft): SetupPolicyFile {
  const tunnel: SetupPolicyFile['tunnel'] =
    d.tunnelMode === 'incremental'
      ? { ...poolRef(d.tunnelPool), mode: 'incremental', start: d.tunnelStart }
      : { ...poolRef(d.tunnelPool), mode: 'formula', formula: d.tunnelFormula };
  let lan: SetupPolicyFile['lan'] = null;
  if (d.lanMode === 'incremental') lan = { mode: 'incremental', ...poolRef(d.lanPool), prefix: intOf(d.lanPrefix) };
  else if (d.lanMode === 'formula') lan = { mode: 'formula', ...poolRef(d.lanPool), formula: d.lanFormula };
  else if (d.lanMode === 'fixed') lan = { mode: 'fixed', subnet: d.lanSubnet };
  else if (d.lanMode === 'manual') lan = { mode: 'manual', variable: d.lanVariable };
  const derived: Record<string, string> = {};
  for (const r of d.derived) {
    const k = r.key.trim();
    if (k !== '') derived[k] = r.expr.trim();
  }
  const chr = d.concentrator.name !== ''
    ? d.concentrator.id !== null
      ? { concentratorName: d.concentrator.name, concentratorId: d.concentrator.id }
      : { concentratorName: d.concentrator.name }
    : d.concentrator.id !== null ? { concentratorId: d.concentrator.id } : {};
  return {
    format: POLICY_FILE_FORMAT,
    tunnel,
    lan,
    pppLoginTemplate: d.login,
    systemIdentityTemplate: d.identity.trim() === '' ? null : d.identity,
    pppPasswordMode: d.passwordMode,
    derived: Object.keys(derived).length > 0 ? derived : null,
    pppProfile: d.profile.trim() === '' ? null : d.profile,
    ...chr,
    ...(d.codeFormat !== '' ? { siteCodeFormat: d.codeFormat } : {}),
  } as SetupPolicyFile;
}

/** What the requirement check needs to know of a rule. */
export function policyShape(d: PolicyDraft): { hasLan: boolean; hasIdentity: boolean; derivedKeys: string[] } {
  return {
    hasLan: d.lanMode !== '',
    hasIdentity: d.identity.trim() !== '',
    derivedKeys: d.derived.map((r) => r.key.trim()).filter((k) => k !== ''),
  };
}

export function storedPolicyShape(p: StoredPolicy): { hasLan: boolean; hasIdentity: boolean; derivedKeys: string[] } {
  return {
    hasLan: p.lan !== null,
    hasIdentity: p.systemIdentityTemplate !== null && p.systemIdentityTemplate !== '',
    derivedKeys: Object.keys(p.derived ?? {}),
  };
}
