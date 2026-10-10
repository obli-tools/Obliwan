// ============================================================================
// @obliwan/shared — the grouped OPERATOR OUTAGE (migration 095)
// ============================================================================
//
// When fourteen stores of the same access provider fail over to 4G at the same
// time, the supervision gets ONE alert — « Panne opérateur probable : Orange —
// 14 magasins en 4G » — instead of fourteen. The server half is
// services/fleet/operatorOutage.service.ts; this file holds what both halves
// read: the site field « Opérateur du lien fixe », the PROVIDER INFERENCE
// (pure, one interpretation), and the wire shapes.
//
// ┌─ WHO CARRIES A STORE'S FIXED LINE — best evidence first ──────────────────┐
// │ 1. 'declared'     the site's « Opérateur du lien fixe » (sites.          │
// │                   fixed_provider): the operator SAID it;                 │
// │ 2. 'pppoe_realm'  wan1_mode = pppoe and the PPPoE login's realm          │
// │                   (`…@orange.fr`, Orange's `fti/…`): the line's own       │
// │                   credential names its provider;                          │
// │ 3. 'asn'          the ASN of the public address REMEMBERED from when the │
// │                   store was on its fixed link (never the current one:    │
// │                   during the outage the store is on 4G and its address  │
// │                   is the mobile operator's);                             │
// │ 4. 'prefix'       that remembered address's /24 (IPv4) or /48 (IPv6);    │
// │ 5. 'none'         nothing is known: the store can only join an           │
// │                   « opérateur inconnu » mass failover.                    │
// │ The first that answers wins, and the answer SAYS which one it was.       │
// │ 1-3 are "known" providers. A known provider is folded onto a canonical    │
// │ key when it is one of the French access providers below, so "Orange"     │
// │ typed on a site, a `fti/` login and AS3215 group together.               │
// └───────────────────────────────────────────────────────────────────────────┘

/** Longest declared provider (`sites_fixed_provider_chk`, migration 095). */
export const SITE_FIXED_PROVIDER_MAX = 64;
/** The CSV column of the site import. */
export const SITE_FIXED_PROVIDER_CSV_COLUMN = 'operateur';
/** A bulk declaration carries at most this many site ids. */
export const SITE_FIXED_PROVIDER_BULK_MAX = 5000;

/**
 * A declared provider as stored: trimmed, inner whitespace collapsed, empty =
 * null ("not declared"). Refused: longer than 64 characters, or a control
 * character (a pasted line break would be a second line in every alert).
 */
export function normalizeFixedProvider(
  raw: unknown,
): { ok: true; value: string | null } | { ok: false; error: string } {
  if (raw === null || raw === undefined) return { ok: true, value: null };
  if (typeof raw !== 'string') return { ok: false, error: 'un texte est attendu' };
  const trimmed = raw.trim();
  // eslint-disable-next-line no-control-regex
  if (/[\u0000-\u001f\u007f-\u009f]/.test(trimmed)) {
    return { ok: false, error: 'contient un caractère de contrôle (un retour à la ligne ?)' };
  }
  const v = trimmed.replace(/\s+/g, ' ');
  if (v === '') return { ok: true, value: null };
  if (v.length > SITE_FIXED_PROVIDER_MAX) {
    return { ok: false, error: `plus de ${SITE_FIXED_PROVIDER_MAX} caractères` };
  }
  return { ok: true, value: v };
}

// ============================================================================
// The inference
// ============================================================================

export const PROVIDER_EVIDENCE = ['declared', 'pppoe_realm', 'asn', 'prefix', 'none'] as const;
export type ProviderEvidence = (typeof PROVIDER_EVIDENCE)[number];

/** Evidence that NAMES a provider; 'prefix' and 'none' do not. */
export function isKnownProviderEvidence(e: ProviderEvidence): boolean {
  return e === 'declared' || e === 'pppoe_realm' || e === 'asn';
}

/** French labels of the evidence (server sentences; the screens translate
 *  `operatorOutage.evidence.<value>`). */
export const PROVIDER_EVIDENCE_LABELS: Readonly<Record<ProviderEvidence, { fr: string; en: string }>> = {
  declared: { fr: 'déclaré sur le site', en: 'declared on the site' },
  pppoe_realm: { fr: 'identifiant PPPoE', en: 'PPPoE login' },
  asn: { fr: 'ASN de l’adresse du lien fixe', en: 'ASN of the fixed-line address' },
  prefix: { fr: 'préfixe de l’adresse du lien fixe', en: 'fixed-line address prefix' },
  none: { fr: 'aucun indice', en: 'no evidence' },
};

export interface FixedProviderFacts {
  /** `sites.fixed_provider`. */
  declared: string | null;
  /** The `wan1_mode` site/device variable. */
  wan1Mode: string | null;
  /** The `wan1_pppoe_username` site/device variable. */
  pppoeUsername: string | null;
  /** The public address REMEMBERED while on the fixed link (device_fixed_link). */
  fixedPublicIp: string | null;
  /** That address's ASN, when it was resolved. */
  asn: { asn: number; name: string | null } | null;
}

export interface FixedProviderInference {
  /** What groups: a canonical provider (`orange`), else `name:` / `realm:` /
   *  `asn:` / `prefix:` + the evidence, else `unknown`. */
  key: string;
  /** What the alert says: "Orange", "AS64500 EXAMPLE", "81.250.1.0/24". */
  label: string;
  evidence: ProviderEvidence;
  /** The evidence itself: the declared text, "@orange.fr", "AS3215", a prefix. */
  detail: string | null;
  /** Evidence 1-3: a provider is named. */
  known: boolean;
}

export const UNKNOWN_PROVIDER_KEY = 'unknown';
export const UNKNOWN_PROVIDER_LABEL = 'opérateur inconnu';

/**
 * The French access providers the three "known" evidences fold onto. The
 * aliases are matched on a lowercased, accent-free text (a declared name, a
 * PPPoE realm, an AS name); the ASNs are the providers' fixed-access networks.
 */
const CANONICAL_PROVIDERS: ReadonlyArray<{ key: string; label: string; alias: RegExp; asns: readonly number[] }> = [
  { key: 'orange', label: 'Orange', alias: /orange|wanadoo|france ?telecom|(^|[^a-z])fti([^a-z]|$)|opentransit/, asns: [3215] },
  { key: 'sfr', label: 'SFR', alias: /(^|[^a-z])sfr([^a-z]|$)|neuf|cegetel|numericable|altice/, asns: [15557, 21502] },
  { key: 'bouygues', label: 'Bouygues Telecom', alias: /bouygues|bouygtel|bytel|(^|[^a-z])bbox([^a-z]|$)/, asns: [5410] },
  { key: 'free', label: 'Free', alias: /(^|[^a-z])free([^a-z]|$)|freebox|proxad|iliad/, asns: [12322] },
  { key: 'ovh', label: 'OVHcloud', alias: /(^|[^a-z])ovh/, asns: [16276, 35540] },
];

/** Lowercase, accents removed, whitespace collapsed. */
export function providerText(text: string): string {
  return text
    .normalize('NFD')
    .replace(/[̀-ͯ]/g, '')
    .toLowerCase()
    .replace(/\s+/g, ' ')
    .trim();
}

function canonicalOf(text: string): { key: string; label: string } | null {
  const t = providerText(text);
  if (t === '') return null;
  for (const p of CANONICAL_PROVIDERS) if (p.alias.test(t)) return { key: p.key, label: p.label };
  return null;
}

function canonicalOfAsn(asn: number): { key: string; label: string } | null {
  for (const p of CANONICAL_PROVIDERS) if (p.asns.includes(asn)) return { key: p.key, label: p.label };
  return null;
}

/**
 * The realm of a PPPoE login: what follows the LAST `@`, lowercased
 * (`store12@example.com` → `example.com`). Orange's professional logins carry
 * no realm (`fti/abcdefg`) and are recognised by that prefix (→ `fti`).
 * Null when the login names no provider.
 */
export function pppoeRealm(username: string | null | undefined): string | null {
  if (!username) return null;
  const u = username.trim();
  if (/^fti\//i.test(u)) return 'fti';
  const at = u.lastIndexOf('@');
  if (at < 0 || at === u.length - 1) return null;
  const realm = u.slice(at + 1).toLowerCase();
  return /^[a-z0-9][a-z0-9.-]{0,252}$/.test(realm) ? realm : null;
}

function expandV6(ip: string): number[] | null {
  const bare = ip.split('%')[0];
  if (!/^[0-9a-f:]+$/i.test(bare)) return null;
  const halves = bare.split('::');
  if (halves.length > 2) return null;
  const head = halves[0] ? halves[0].split(':') : [];
  const tail = halves.length === 2 && halves[1] ? halves[1].split(':') : [];
  const missing = 8 - head.length - tail.length;
  if (halves.length === 1 ? head.length !== 8 : missing < 1) return null;
  const groups = [...head, ...Array(halves.length === 2 ? missing : 0).fill('0'), ...tail];
  const out: number[] = [];
  for (const g of groups) {
    if (!/^[0-9a-f]{1,4}$/i.test(g)) return null;
    out.push(parseInt(g, 16));
  }
  return out.length === 8 ? out : null;
}

/**
 * The /24 of an IPv4 address or the /48 of an IPv6 one, or null. The
 * weakest evidence: it groups the stores of one provider's same block, never
 * two blocks of the same provider.
 */
export function publicPrefixOf(ip: string | null | undefined): string | null {
  if (!ip) return null;
  const bare = ip.trim().split('/')[0];
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(bare);
  if (m) {
    const o = m.slice(1, 5).map(Number);
    if (o.some((n) => n > 255)) return null;
    return `${o[0]}.${o[1]}.${o[2]}.0/24`;
  }
  const g = expandV6(bare);
  if (!g) return null;
  return `${g[0].toString(16)}:${g[1].toString(16)}:${g[2].toString(16)}::/48`;
}

/** "ORANGE, FR" → "ORANGE" — the registry's country suffix says nothing here. */
function asnLabel(asn: number, name: string | null): string {
  const n = (name ?? '').replace(/,\s*[A-Z]{2}\s*$/, '').trim();
  return n ? `${n} (AS${asn})` : `AS${asn}`;
}

/**
 * Who carries this store's fixed line, with the evidence used. Pure: the
 * caller loads the facts (site row, WAN variables, the fixed-link memory).
 */
export function inferFixedProvider(f: FixedProviderFacts): FixedProviderInference {
  const declared = f.declared?.trim() ?? '';
  if (declared !== '') {
    const c = canonicalOf(declared);
    return {
      key: c ? c.key : `name:${providerText(declared)}`,
      label: c ? c.label : declared,
      evidence: 'declared',
      detail: declared,
      known: true,
    };
  }
  if ((f.wan1Mode ?? '').trim().toLowerCase() === 'pppoe') {
    const realm = pppoeRealm(f.pppoeUsername);
    if (realm) {
      const c = canonicalOf(realm);
      return {
        key: c ? c.key : `realm:${realm}`,
        label: c ? c.label : realm,
        evidence: 'pppoe_realm',
        detail: realm === 'fti' ? 'fti/…' : `@${realm}`,
        known: true,
      };
    }
  }
  if (f.asn && Number.isInteger(f.asn.asn) && f.asn.asn > 0) {
    const c = canonicalOfAsn(f.asn.asn) ?? (f.asn.name ? canonicalOf(f.asn.name) : null);
    return {
      key: c ? c.key : `asn:${f.asn.asn}`,
      label: c ? c.label : asnLabel(f.asn.asn, f.asn.name),
      evidence: 'asn',
      detail: `AS${f.asn.asn}`,
      known: true,
    };
  }
  const prefix = publicPrefixOf(f.fixedPublicIp);
  if (prefix) {
    return { key: `prefix:${prefix}`, label: prefix, evidence: 'prefix', detail: prefix, known: false };
  }
  return { key: UNKNOWN_PROVIDER_KEY, label: UNKNOWN_PROVIDER_LABEL, evidence: 'none', detail: null, known: false };
}

// ============================================================================
// Wire shapes — GET /api/operator-outages[/:id]
// ============================================================================

/** The alerts of a group (`live_alerts.outage_role`): the god view's, a
 *  customer tenant's slice, a per-store alert folded under the group. */
export const OPERATOR_OUTAGE_ROLES = ['global', 'tenant', 'member'] as const;
export type OperatorOutageRole = (typeof OPERATOR_OUTAGE_ROLES)[number];

/** How a store lost its fixed line: on its 4G backup, or offline (no backup,
 *  or not yet reconnected through it). */
export type OperatorOutageMemberKind = 'cellular' | 'offline';

export interface OperatorOutageMemberDto {
  deviceId: number;
  deviceName: string;
  siteId: number | null;
  siteName: string | null;
  /** God view only. */
  tenantId?: number;
  tenantName?: string | null;
  kind: OperatorOutageMemberKind;
  lostAt: string;
  joinedAt: string;
  recoveredAt: string | null;
  /** The group closed while this store was still out: followed individually. */
  releasedAt: string | null;
  evidence: ProviderEvidence;
  evidenceDetail: string | null;
  /** Its per-store 4G alert was raised under the group, not sent separately. */
  alertFolded: boolean;
}

export interface OperatorOutagePoint {
  at: string;
  count: number;
}

export interface OperatorOutageSummaryDto {
  id: number;
  providerKey: string;
  providerLabel: string;
  /** « Bascule 4G simultanée — opérateur inconnu ». */
  unknownProvider: boolean;
  status: 'open' | 'closed';
  /** The viewer's scope: 'global' (god view, every tenant) or 'tenant'. */
  scope: 'global' | 'tenant';
  startedAt: string;
  openedAt: string;
  closedAt: string | null;
  closeReason: 'recovered' | 'receded' | null;
  /** In the viewer's scope. */
  activeCount: number;
  cellularCount: number;
  offlineCount: number;
  totalCount: number;
  peakCount: number;
  /** How the members' provider was established, counted per evidence. */
  evidence: Partial<Record<ProviderEvidence, number>>;
  threshold: number;
  windowMinutes: number;
}

export interface OperatorOutageDetailDto extends OperatorOutageSummaryDto {
  members: OperatorOutageMemberDto[];
  points: OperatorOutagePoint[];
}

/** The provider of one store as the 4G-backup fleet list shows it. */
export interface StoreProviderDto {
  key: string;
  label: string;
  evidence: ProviderEvidence;
  detail: string | null;
  known: boolean;
}
