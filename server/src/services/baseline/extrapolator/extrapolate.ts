// ============================================================================
// Brick 10 — the extrapolator: one cluster of routers in, one template out
// ============================================================================
//
// What an operator does by hand for every new customer (operator
// templates: a Nunjucks body, an `.owt.json` var_schema with levels, the
// formulas from the site code, the per-site exceptions, the secrets sent to the
// vault) is done here from the routers themselves, for ONE cluster the miner
// found. PURE: no database, no socket, no vault — the service hands in the
// exports and the site records, and persists what comes out. The proof that
// the proposal reproduces each router is `reproduce.ts`, which renders it in
// the template worker.
//
// THE DECISION, PER VALUE (each with its confidence and its evidence)
//   identical at every site ............................ a literal in the body
//   a function of the site (the allocator's grammars) ... a COMPUTED value:
//       the login / identity templates, an address formula over the site
//       number, an address of the site LAN (`lan_subnet | cidrHost(n)`), the
//       site code inlined (`LAN-{{ site_code }}`)
//   a few values ......................... a default + the sites that differ
//   one value per site, no formula ................... a SITE variable, valued
//       from each site's own snapshot
//   a credential the redacted export hides ........... a SECRET variable,
//       declared, never valued
//   a difference at ≤ `deviationMaxSites` sites ........ a DEVIATION: reported
//       per site with its line, NOT baked into the template — a hand edit on
//       one router must not become every router's configuration.
//   a line of the WAN1 uplink (wan1.ts) ................ the STANDARD WAN1
//       block, when the cluster mixes dhcp / pppoe / static stores: the lines
//       are present by MODE (`wan1_mode`, a site value for every pppoe or
//       static store, dhcp being the schema default), the PPPoE login, name
//       and VLAN, the fixed address and gateway are site values, the PPPoE
//       password a secret never valued. A store whose WAN1 is not the standard
//       block is left out of it by name. A pure-DHCP cluster never sees it.
//
// ┌─ WHAT THIS FILE WILL NOT DO ──────────────────────────────────────────────┐
// │ It never sees a secret's value (the funnel in exportText.ts dropped it),  │
// │ so no proposal, evidence string or site value can carry one. It writes no │
// │ template, no variable and nothing to a router: approving is the service's │
// │ job, behind TEMPLATE_WRITE, and produces a DRAFT revision.                │
// └───────────────────────────────────────────────────────────────────────────┘

import { createHash } from 'crypto';
import {
  DISCOVER_KEYWORD, DISCOVER_MENUS, DISCOVER_PROPERTY_RE, MANAGEMENT_TUNNEL_NAME,
  discoverProbeProblems, isSensitiveDiscoverProperty,
  type ExtrapolatedDeviation, type ExtrapolatedDeviationKind, type ExtrapolatedLevel,
  type ExtrapolatedPolicyFragment, type ExtrapolatedRuleKind, type ExtrapolatedSiteValue,
  type ExtrapolatedVariable, type ExtrapolationOverride, type ExtrapolationParams,
} from '@obliwan/shared';
import { SHARED_PPP_PASSWORD_KEY } from '../../allocation/policy';
import {
  displayLine, encodeRosValue, isOrderedSection, menuHeader, menuShortName, parseRouterOsExport, propRaw, propValue,
  rosQuoteBody, type ExportEntry, type ParsedRouterOsExport,
} from './exportText';
import { alignSites, type PathBlock, type TemplateRow } from './rows';
import {
  evaluateAddressFormula, evaluateLanParts, evaluateTextPattern, findAddressFormula, findLanRelation,
  findTextPattern, lanBlockOf, lanOfInterfaceAddress, siteFactsOf,
  type LanBlock, type LanPart, type SiteFacts, type TextPattern,
} from './formulas';
import {
  WAN1_ADDRESS_PATTERN, WAN1_GATEWAY_PATTERN, WAN1_KEYS, WAN1_MODES, WAN1_NETWATCH_COMMENT, WAN1_PORT,
  WAN1_ROUTE_GW, WAN1_ROUTE_NW, WAN1_USERNAME_PATTERN, WAN1_VLAN_ID_PATTERN,
  isStandardWan1Probe, planWan1Cluster, standardWan1Probes, wan1BodyPreamble,
  type Wan1ClusterPlan, type Wan1Mode, type Wan1Role, type Wan1Summary,
} from './wan1';
import { PPPOE_UPLINK_NAMES, WAN_LIST_NAME } from '../../plan/uplinkGuard';

// ============================================================================
// Inputs and outputs
// ============================================================================

export interface ExtrapolationSiteInput {
  deviceId: number;
  deviceName: string;
  siteId: number | null;
  site: { code: string | null; name: string | null; country: string | null } | null;
  /** What ObliWAN already records for the site (allocation, device row). */
  recorded: { pppUsername: string | null; systemIdentity: string | null; lanSubnet: string | null };
  snapshotId: number | null;
  /** The REDACTED raw export (`config_snapshots.raw_gz`). */
  exportText: string;
}

/** A probe an existing template of the tenant already states — its key is the
 *  operator's own name for that place in the configuration. */
export interface ExistingProbe {
  key: string;
  menu: string;
  where: Record<string, string>;
  property: string;
  label: string | null;
  source: string;
}

/** A NON-SECRET variable value the tenant already stores. */
export interface ExistingValue {
  key: string;
  scope: 'instance' | 'global' | 'tenant';
  value: string;
}

export interface ClusterInput {
  label: string;
  clusterIndex: number;
  sites: ExtrapolationSiteInput[];
  /** The miner's medoid: its order becomes the template's order. */
  referenceDeviceId: number | null;
  params: ExtrapolationParams;
  existingProbes?: ExistingProbe[];
  existingValues?: ExistingValue[];
  runLabel?: string;
}

export interface ClusterDraft {
  label: string;
  clusterIndex: number;
  body: string;
  bodySha256: string;
  varSchema: Record<string, unknown>;
  variables: ExtrapolatedVariable[];
  policy: ExtrapolatedPolicyFragment;
  deviations: ExtrapolatedDeviation[];
  warnings: string[];
  /** Rows of the body (template lines, sections excluded). */
  lineCount: number;
  /** Per site, the REDACTED render context the proof renders with. Never
   *  persisted: it is rebuilt from the variables. */
  contexts: Array<Record<string, unknown>>;
  /** Per site, the parsed export (the proof's reference). */
  parsed: ParsedRouterOsExport[];
  refusedSecretValues: number;
  /** The standard WAN1 block (wan1.ts): emitted or not, routers per mode,
   *  the routers left out and why. Null when no router of the cluster runs
   *  pppoe or static — the proposal is then exactly what it always was. */
  wan1: Wan1Summary | null;
}

// ============================================================================
// Variables under construction
// ============================================================================

interface VarSpec {
  name: string;
  slot: string;
  kind: ExtrapolatedRuleKind;
  level: ExtrapolatedLevel;
  type: 'string' | 'boolean';
  secret: boolean;
  label: string;
  expression: string | null;
  defaultValue: string | boolean | null;
  /** site index -> value (site: all; default_exceptions / presence: the
   *  exceptions; an override: the misfits). */
  perSite: Map<number, string | boolean>;
  /** computed: the value ObliWAN supplies for a site. */
  computed: ((site: number) => string | null) | null;
  confidence: number;
  evidence: string[];
  uses: string[];
  fit: { matched: number; total: number } | null;
  probe: Record<string, unknown> | null;
  reusedFrom: string | null;
  required: boolean;
  /** For an `override`: the name of the rule it overrides. */
  overrides: string | null;
  /** A variable of the standard WAN1 block: its name, declaration and
   *  description are the block's, never renamed, never adopted. */
  standard?: boolean;
  /** Extra var_schema keywords (enum, pattern) of a standard variable. */
  schemaExtra?: Record<string, unknown>;
  /** A standard variable's own description (French). */
  description?: string;
}

type SlotPlan =
  | { kind: 'omit' }
  | { kind: 'constant'; raw: string }
  | { kind: 'var'; v: VarSpec; override: VarSpec | null }
  | { kind: 'optional'; v: VarSpec }
  | { kind: 'lan'; parts: LanPart[]; override: VarSpec | null }
  | { kind: 'code'; pattern: TextPattern; override: VarSpec | null }
  /** WAN1 block: a Nunjucks value expression the block fixes. */
  | { kind: 'expr'; text: string }
  /** WAN1 block: a value the mode fixes (`cases`), else what the routers of
   *  the other modes say (`rest`, inferred on those routers only). */
  | { kind: 'split'; cases: Array<{ cond: string; text: string }>; rest: SlotPlan };

interface RowPlan {
  row: TemplateRow;
  block: PathBlock;
  mode: 'always' | 'conditional' | 'excluded';
  flag: VarSpec | null;
  role: 'mgmt' | null;
  slots: Map<string, SlotPlan>;
  secrets: Array<{ key: string; v: VarSpec; optional: boolean }>;
  /** WAN1 block: the line's role in the block (null = an ordinary line). */
  wan: Wan1Role | null;
  /** WAN1 block: the condition the line renders under (null = always). */
  cond: string | null;
}

interface SiteState {
  input: ExtrapolationSiteInput;
  parsed: ParsedRouterOsExport;
  facts: SiteFacts;
  lan: LanBlock | null;
}

const NJK_RESERVED = new Set([
  'if', 'else', 'elif', 'endif', 'for', 'endfor', 'in', 'not', 'and', 'or', 'is', 'true', 'false',
  'none', 'null', 'loop', 'range', 'set', 'block', 'extends', 'include', 'import', 'from', 'as',
  'with', 'without', 'context', 'raw', 'macro', 'call', 'filter', 'caller', 'super', 'cycler', 'joiner',
  'site', 'box', 'device', 'constructor', 'prototype',
]);

/** Names the allocator owns (or ObliWAN supplies): never given to anything
 *  but their own role. */
const ROLE_NAMES = new Set([
  'site_code', 'ppp_username', SHARED_PPP_PASSWORD_KEY, 'system_identity', 'lan_subnet', 'tunnel_ip',
]);

const ABSENT = '\u0000absent';

/** `redactedPlaceholder(key)` of the variable resolver, spelled here so this
 *  module never imports a file that opens a database connection. The harness
 *  asserts the two agree. */
export function secretPlaceholder(key: string): string {
  return `__OBLIWAN_SECRET_${key.toUpperCase()}__`;
}

function sanitizeName(s: string): string {
  let n = s.normalize('NFKD').replace(/[̀-ͯ]/g, '').toLowerCase()
    .replace(/[^a-z0-9]+/g, '_').replace(/_+/g, '_').replace(/^_+|_+$/g, '');
  if (!/^[a-z]/.test(n)) n = `v_${n}`;
  n = n.slice(0, 56).replace(/_+$/, '');
  if (n === '' || n === 'v') n = 'valeur';
  if (NJK_RESERVED.has(n)) n = `${n}_v`;
  return n;
}

function pct(a: number, b: number): string {
  return `${a}/${b}`;
}

function shortValue(v: string): string {
  return v.length > 48 ? `${v.slice(0, 45)}…` : v;
}

// ============================================================================
// Secret companions — what a redacted export hides and a template must carry
// ============================================================================

interface SecretCompanion {
  path: string;
  key: string;
  /** The sibling property that says who the credential belongs to. */
  owner: string | null;
  when: (e: ExportEntry) => boolean;
  /** The export cannot tell whether it is set at all (a SIM PIN): declared
   *  OPTIONAL, written only when a value is stored. */
  optional?: boolean;
}

const has = (k: string) => (e: ExportEntry): boolean => propValue(e, k) !== undefined;
const includesWord = (k: string, word: RegExp) => (e: ExportEntry): boolean =>
  word.test(propValue(e, k) ?? '');

/**
 * A closed table, on purpose: a property is re-declared only where it is a
 * credential the line cannot work without. A guess here would add a secret
 * nobody can fill to every router; a gap is a line the operator completes.
 */
const SECRET_COMPANIONS: readonly SecretCompanion[] = [
  { path: '/interface/l2tp-client', key: 'password', owner: 'user', when: has('user') },
  {
    path: '/interface/l2tp-client', key: 'ipsec-secret', owner: 'connect-to',
    when: (e) => ['yes', 'required'].includes(propValue(e, 'use-ipsec') ?? ''),
  },
  { path: '/interface/pppoe-client', key: 'password', owner: 'user', when: has('user') },
  { path: '/interface/sstp-client', key: 'password', owner: 'user', when: has('user') },
  { path: '/interface/ovpn-client', key: 'password', owner: 'user', when: has('user') },
  { path: '/interface/pptp-client', key: 'password', owner: 'user', when: has('user') },
  { path: '/ppp/secret', key: 'password', owner: 'name', when: (e) => e.verb === 'add' },
  { path: '/user', key: 'password', owner: 'name', when: (e) => e.verb === 'add' },
  // `/user set [ find name=admin ]`: the selector names the account.
  {
    path: '/user', key: 'password', owner: null,
    when: (e) => e.verb === 'set' && (e.positional.length > 0 || /(^| )name=/.test(e.selectorCanon)),
  },
  // The SIM PIN of an LTE modem the template configures. The export cannot say
  // whether a PIN is set (it hides it either way): declared, evidence says so.
  {
    path: '/interface/lte', key: 'pin', owner: null, optional: true,
    when: (e) => e.verb === 'set' && propValue(e, 'apn-profiles') !== undefined,
  },
  {
    path: '/interface/wireless/security-profiles', key: 'wpa2-pre-shared-key', owner: 'name',
    when: includesWord('authentication-types', /(^|,)wpa2-psk(,|$)/),
  },
  {
    path: '/interface/wireless/security-profiles', key: 'wpa-pre-shared-key', owner: 'name',
    when: includesWord('authentication-types', /(^|,)wpa-psk(,|$)/),
  },
  {
    path: '/interface/wifi', key: 'security.passphrase', owner: 'configuration.ssid',
    when: includesWord('security.authentication-types', /psk/),
  },
  {
    path: '/interface/wifi/security', key: 'passphrase', owner: 'name',
    when: includesWord('authentication-types', /psk/),
  },
  {
    path: '/ip/ipsec/identity', key: 'secret', owner: 'peer',
    when: (e) => (propValue(e, 'auth-method') ?? 'pre-shared-key') === 'pre-shared-key',
  },
  { path: '/interface/wireguard', key: 'private-key', owner: null, when: (e) => e.verb === 'add' },
];

// ============================================================================
// The extrapolator
// ============================================================================

class Extrapolator {
  private readonly p: ExtrapolationParams;
  private readonly devMax: number;
  private readonly sites: SiteState[];
  private readonly n: number;
  private readonly overrides = new Map<string, ExtrapolationOverride>();
  private readonly vars: VarSpec[] = [];
  private readonly unify = new Map<string, VarSpec>();
  private readonly names = new Set<string>();
  private readonly deviations: ExtrapolatedDeviation[] = [];
  private readonly warnings: string[] = [];
  private blocks: PathBlock[] = [];
  private plans: RowPlan[] = [];
  private lanVar: VarSpec | null = null;
  private siteCodeVar: VarSpec | null = null;
  private lanAnchor: string | null = null;
  /** The order sites were folded in (the reference first). */
  private order: number[] = [];
  /** The standard WAN1 block's decision for this cluster. */
  private wan1: Wan1ClusterPlan | null = null;
  /** The rows of the WAN1 block, by role. */
  private readonly wanRow = new Map<TemplateRow, Wan1Role>();
  /** The standard WAN1 variables, by name. */
  private readonly wanVars = new Map<string, VarSpec>();
  private readonly policy: ExtrapolatedPolicyFragment = {
    pppLoginTemplate: null,
    systemIdentityTemplate: null,
    lanFormula: null,
    derived: {},
    lanRecorded: [],
    adopted: [],
    current: null,
  };

  constructor(private readonly input: ClusterInput) {
    this.p = input.params;
    this.devMax = input.params.deviationMaxSites;
    for (const o of input.params.overrides) this.overrides.set(o.slot, o);
    this.sites = input.sites.map((s) => {
      const parsed = parseRouterOsExport(s.exportText);
      return { input: s, parsed, facts: siteFactsOf(s.site), lan: null };
    });
    this.n = this.sites.length;
  }

  // ── names ─────────────────────────────────────────────────────────────────

  private claim(base: string, role = false): string {
    let n = sanitizeName(base);
    if (!role && ROLE_NAMES.has(n)) n = `${n}_v`;
    let candidate = n;
    for (let i = 2; this.names.has(candidate); i++) candidate = `${n.slice(0, 52)}_${i}`;
    this.names.add(candidate);
    return candidate;
  }

  private overrideFor(slot: string): ExtrapolationOverride | undefined {
    return this.overrides.get(slot);
  }

  private newVar(spec: Omit<VarSpec, 'uses' | 'probe' | 'reusedFrom' | 'perSite' | 'computed' | 'overrides'> & Partial<VarSpec>): VarSpec {
    const v: VarSpec = {
      uses: [],
      probe: null,
      reusedFrom: null,
      perSite: new Map(),
      computed: null,
      overrides: null,
      ...spec,
    };
    const forced = this.overrideFor(v.slot);
    if (forced?.name && !ROLE_NAMES.has(v.name) && !this.names.has(forced.name)) {
      this.names.delete(v.name);
      this.names.add(forced.name);
      v.name = forced.name;
      v.evidence.push(`Nom choisi par l'opérateur (« ${forced.name} »).`);
    }
    this.vars.push(v);
    return v;
  }

  private shared(key: string, make: () => VarSpec): VarSpec {
    const existing = this.unify.get(key);
    if (existing) return existing;
    const v = make();
    this.unify.set(key, v);
    return v;
  }

  // ── where a site is ───────────────────────────────────────────────────────

  private siteLabel(s: number): string {
    const st = this.sites[s].input;
    return st.site?.code ?? st.deviceName;
  }

  private siteValue(s: number, value: string): ExtrapolatedSiteValue {
    const st = this.sites[s].input;
    return { deviceId: st.deviceId, siteId: st.siteId, siteCode: st.site?.code ?? null, value };
  }

  private deviate(s: number, kind: ExtrapolatedDeviationKind, slot: string, line: string, detail: string): void {
    const st = this.sites[s].input;
    this.deviations.push({
      deviceId: st.deviceId,
      siteId: st.siteId,
      siteCode: st.site?.code ?? null,
      kind,
      slot,
      line: line.slice(0, 2000),
      detail,
    });
  }

  // ── rows ──────────────────────────────────────────────────────────────────

  private rowBase(row: TemplateRow): string {
    const segs = row.path.split('/').filter(Boolean);
    const last = segs[segs.length - 1] ?? 'racine';
    const members = [...row.members.values()];
    const name = propValue(row.ref, 'name');
    if (name !== undefined && members.every((e) => propValue(e, 'name') === name)) return name;
    if (row.selectorCanon) {
      const vals = row.selectorCanon.split(' ').map((kv) => {
        const [k, v] = kv.split('=');
        return v === 'yes' ? k : v ?? k;
      });
      return `${last}_${vals.join('_')}`;
    }
    if (row.positional.length > 0) return `${last}_${row.positional.join('_')}`;
    if (row.verb === 'set') return segs.slice(-2).join('_');
    // An unnamed `add`: the interface it sits on, else its comment.
    for (const k of ['interface', 'comment']) {
      const v = propValue(row.ref, k);
      if (v !== undefined && v.length <= 32 && members.every((e) => propValue(e, k) === v)) {
        return k === 'interface' ? v : `${last}_${v}`;
      }
    }
    return last;
  }

  private rowTag(row: TemplateRow): string {
    const members = [...row.members.values()];
    const name = propValue(row.ref, 'name');
    if (name !== undefined && members.every((e) => propValue(e, 'name') === name)) return name;
    if (row.selectorRaw) return row.selectorRaw;
    if (row.positional.length > 0) return row.positional.join(' ');
    return '';
  }

  private useOf(row: TemplateRow, key: string): string {
    const tag = this.rowTag(row);
    return `${menuHeader(row.path)} ${row.verb}${tag ? ` ${tag}` : ''} → ${key}`;
  }

  private isManagementRow(row: TemplateRow): boolean {
    if (row.path !== '/interface/l2tp-client' || row.verb !== 'add') return false;
    const members = [...row.members.entries()];
    if (members.every(([, e]) => propValue(e, 'name') === MANAGEMENT_TUNNEL_NAME)) return true;
    let agree = 0;
    let known = 0;
    for (const [s, e] of members) {
      const rec = this.sites[s].input.recorded.pppUsername;
      if (!rec) continue;
      known++;
      if ((propValue(e, 'user') ?? '').toLowerCase() === rec.toLowerCase()) agree++;
    }
    return known >= 2 && agree >= Math.ceil(0.8 * known);
  }

  // ── 1. presence ───────────────────────────────────────────────────────────

  private planRows(): void {
    for (const block of this.blocks) {
      for (const row of block.rows) {
        const wan = this.wanRow.get(row) ?? null;
        if (wan !== null) {
          // A line of the WAN1 block: present by MODE, never by count — the
          // PPPoE client of three stores out of forty is not a hand edit.
          const cond = wan1RowCondition(wan, this.wan1?.vlan === true);
          this.plans.push({
            row, block, mode: cond === null ? 'always' : 'conditional', flag: null, role: null,
            slots: new Map(), secrets: [], wan, cond,
          });
          continue;
        }
        const present = row.members.size;
        const keep = this.overrideFor(row.key)?.keepLine === true;
        let mode: RowPlan['mode'];
        if (present === this.n) mode = 'always';
        else if (this.n >= 3 && present <= this.devMax && !keep) mode = 'excluded';
        else if (this.n >= 3 && this.n - present <= this.devMax && !keep) mode = 'always';
        else mode = 'conditional';
        const plan: RowPlan = {
          row, block, mode, flag: null, role: this.isManagementRow(row) ? 'mgmt' : null,
          slots: new Map(), secrets: [], wan: null, cond: null,
        };
        this.plans.push(plan);

        if (mode === 'excluded') {
          for (const [s, e] of row.members) {
            this.deviate(s, 'extra_line', row.key, displayLine(e),
              `Ligne présente sur ${pct(present, this.n)} site(s) seulement : retouche locale probable, ` +
              'non reprise dans le modèle. À reporter dans le modèle ou à retirer du routeur.');
          }
        } else if (mode === 'always' && present < this.n) {
          for (let s = 0; s < this.n; s++) {
            if (row.members.has(s)) continue;
            this.deviate(s, 'missing_line', row.key, displayLine(row.ref),
              `Ligne du modèle absente de ce site (présente sur ${pct(present, this.n)}) : ` +
              'suppression locale probable. Le modèle la conserve.');
          }
        } else if (mode === 'conditional') {
          plan.flag = this.presenceVar(row);
        }
      }
    }
  }

  private presenceVar(row: TemplateRow): VarSpec {
    const vector = this.sites.map((_, s) => row.members.has(s));
    const present = vector.filter(Boolean).length;
    const def = present * 2 >= this.n;
    const v = this.shared(`presence|${vector.map((b) => (b ? '1' : '0')).join('')}`, () => {
      const name = this.claim(`${this.rowBase(row)}_present`);
      const spec = this.newVar({
        name,
        slot: row.key,
        kind: 'presence',
        level: 'site',
        type: 'boolean',
        secret: false,
        label: `Présence : ${menuShortName(row.path)} ${this.rowTag(row)}`.trim(),
        expression: null,
        defaultValue: def,
        confidence: Math.min(1, Math.max(present, this.n - present) / this.n),
        evidence: [
          `Ligne présente sur ${pct(present, this.n)} sites : variante de configuration, ` +
          `vraie par défaut${def ? '' : ' : non'} ; les sites qui diffèrent reçoivent une valeur de site.`,
        ],
        fit: null,
        required: false,
      });
      vector.forEach((b, s) => { if (b !== def) spec.perSite.set(s, b); });
      return spec;
    });
    v.uses.push(`${menuHeader(row.path)} ${row.verb} ${this.rowTag(row)}`.trim());
    return v;
  }

  // ── 2. the site LAN ───────────────────────────────────────────────────────

  private detectLan(): void {
    const isPrivate = (cidr: string): boolean =>
      /^10\./.test(cidr) || /^192\.168\./.test(cidr) || /^172\.(1[6-9]|2\d|3[01])\./.test(cidr);
    let best: { plan: RowPlan; lans: Map<number, string>; score: number } | null = null;
    for (const plan of this.plans) {
      const row = plan.row;
      if (plan.mode === 'excluded' || plan.wan !== null || row.path !== '/ip/address' || row.verb !== 'add') continue;
      if (row.members.size < Math.max(2, Math.ceil(0.8 * this.n))) continue;
      const lans = new Map<number, string>();
      let ok = true;
      for (const [s, e] of row.members) {
        const lan = lanOfInterfaceAddress(propValue(e, 'address') ?? '');
        if (lan === null || !isPrivate(lan)) { ok = false; break; }
        lans.set(s, lan);
      }
      if (!ok || new Set(lans.values()).size < 2) continue;
      const iface = (propValue(row.ref, 'interface') ?? '').toLowerCase();
      const score = (/lan|bridge/.test(iface) ? 1 : 0);
      if (best === null || score > best.score) best = { plan, lans, score };
    }
    if (!best) return;
    this.lanAnchor = best.plan.row.key;
    for (let s = 0; s < this.n; s++) {
      const lan = best.lans.get(s) ?? this.sites[s].input.recorded.lanSubnet ?? null;
      const block = lanBlockOf(lan);
      this.sites[s].lan = block;
      this.sites[s].facts.lan = block?.text ?? null;
      this.sites[s].facts.lanNetwork = block ? block.text.split('/')[0] : null;
    }
  }

  private ensureLanVar(): VarSpec {
    if (this.lanVar) return this.lanVar;
    const lans = this.sites.map((st) => st.lan?.text ?? null);
    const known = lans.filter((l): l is string => l !== null).length;
    const fit = findAddressFormula(lans, this.sites.map((st) => st.facts));
    const evidence: string[] = [
      `LAN relevé sur ${pct(known, this.n)} sites (adresse de l'interface LAN, ligne ${this.lanAnchor ?? '—'}).`,
    ];
    let expression: string | null = null;
    let confidence = 0.5;
    const recordedSites: number[] = [];
    if (fit && fit.fits.length >= Math.max(2, Math.ceil(this.p.formulaMinFit * known))) {
      expression = fit.formula.source;
      confidence = fit.fits.length / Math.max(1, known);
      evidence.push(
        `Formule « ${expression} » sur le numéro de site, vérifiée par l'évaluateur de l'allocateur ` +
        `sur ${pct(fit.fits.length, known)} sites.`,
      );
      const fitSet = new Set(fit.fits);
      lans.forEach((l, s) => { if (l !== null && !fitSet.has(s)) recordedSites.push(s); });
      if (recordedSites.length > 0) {
        evidence.push(
          `${recordedSites.length} site(s) ont un LAN hors formule (LAN fixe ou historique) : ` +
          'à enregistrer par la reprise LAN, ils le gardent.',
        );
      }
      this.policy.lanFormula = expression;
    } else {
      lans.forEach((l, s) => { if (l !== null) recordedSites.push(s); });
      evidence.push('Aucune formule ne reproduit les LAN : chaque LAN est à enregistrer par la reprise LAN.');
    }
    for (const s of recordedSites) {
      const st = this.sites[s].input;
      this.policy.lanRecorded.push({ siteId: st.siteId, siteCode: st.site?.code ?? null, lan: lans[s]! });
    }
    let agree = 0;
    let rec = 0;
    this.sites.forEach((st) => {
      if (!st.input.recorded.lanSubnet || !st.lan) return;
      rec++;
      if (st.input.recorded.lanSubnet === st.lan.text) agree++;
    });
    if (rec > 0) evidence.push(`Identique au LAN alloué dans ObliWAN pour ${pct(agree, rec)} sites.`);

    const v = this.newVar({
      name: 'lan_subnet',
      slot: this.lanAnchor ?? 'lan',
      kind: 'lan',
      level: 'computed',
      type: 'string',
      secret: false,
      label: 'LAN du site (CIDR)',
      expression,
      defaultValue: null,
      confidence,
      evidence,
      fit: expression ? { matched: known - recordedSites.length, total: known } : null,
      required: true,
    });
    this.names.add('lan_subnet');
    v.computed = (s) => this.sites[s].lan?.text ?? null;
    for (const s of recordedSites) v.perSite.set(s, lans[s]!);
    this.lanVar = v;
    return v;
  }

  private ensureSiteCodeVar(): VarSpec {
    if (this.siteCodeVar) return this.siteCodeVar;
    this.names.add('site_code');
    const v = this.newVar({
      name: 'site_code',
      slot: 'site_code',
      kind: 'formula',
      level: 'computed',
      type: 'string',
      secret: false,
      label: 'Code site',
      expression: '{site.code}',
      defaultValue: null,
      confidence: 1,
      evidence: ['Le code du site, fourni par ObliWAN (fiche site) au rendu.'],
      fit: null,
      required: true,
    });
    v.computed = (s) => this.sites[s].facts.code;
    this.siteCodeVar = v;
    return v;
  }

  // ── 3. values ─────────────────────────────────────────────────────────────

  private planSlots(): void {
    for (const plan of this.plans) {
      if (plan.mode === 'excluded') continue;
      const row = plan.row;
      if (row.opaqueText !== null) continue;
      if (plan.wan !== null) {
        this.planWanSlots(plan);
        continue;
      }
      for (const key of row.keyOrder) plan.slots.set(key, this.planSlot(plan, key));
    }
  }

  private planSlot(plan: RowPlan, key: string): SlotPlan {
    const row = plan.row;
    const slot = `${row.key}#${key}`;
    const ov = this.overrideFor(slot);
    const forced = ov?.rule ?? 'auto';
    const P = [...row.members.keys()].sort((a, b) => a - b);
    const val = (s: number): string | null => propValue(row.members.get(s)!, key) ?? null;
    const rawOf = (s: number): string => propRaw(row.members.get(s)!, key) ?? '';
    const withValue = P.filter((s) => val(s) !== null);
    if (withValue.length === 0) return { kind: 'omit' };

    if (P.length >= 3 && withValue.length <= this.devMax && forced === 'auto') {
      for (const s of withValue) {
        this.deviate(s, 'extra_property', slot, displayLine(row.members.get(s)!),
          `Propriété « ${key} » posée sur ${pct(withValue.length, P.length)} site(s) seulement ` +
          `(« ${shortValue(val(s)!)} ») : non reprise dans le modèle.`);
      }
      return { kind: 'omit' };
    }
    let S = P;
    if (P.length >= 3 && withValue.length < P.length && P.length - withValue.length <= this.devMax
      && forced === 'auto') {
      for (const s of P) {
        if (val(s) !== null) continue;
        this.deviate(s, 'missing_property', slot, displayLine(row.members.get(s)!),
          `Propriété « ${key} » absente sur ce site (présente sur ${pct(withValue.length, P.length)}) : ` +
          'le modèle la pose.');
      }
      S = withValue;
    }

    const values = S.map(val);
    const optional = values.some((v) => v === null);
    const counts = new Map<string, number>();
    for (const v of values) counts.set(v ?? ABSENT, (counts.get(v ?? ABSENT) ?? 0) + 1);
    const ranked = [...counts.entries()].sort((a, b) =>
      b[1] - a[1] || (a[0] === ABSENT ? 1 : 0) - (b[0] === ABSENT ? 1 : 0) || a[0].localeCompare(b[0]));
    const [modalKey, modalCount] = ranked[0];
    const modal = modalKey === ABSENT ? null : modalKey;
    const rawOfValue = (v: string): string => rawOf(S.find((s) => val(s) === v)!);

    if (counts.size === 1) return this.constant(row, key, slot, modal!, rawOfValue(modal!), S);

    if (forced === 'literal') return this.constantWithDeviations(row, key, slot, S, modal, rawOfValue);
    if (forced === 'site') return this.siteSlot(plan, key, slot, S, values, true);
    if (forced === 'default_exceptions') return this.defaultSlot(plan, key, slot, S, values, modal, true);

    if (!optional) {
      const formula = this.formulaSlot(plan, key, slot, S, values as string[]);
      if (formula) return formula;
    }

    const minority = S.length - modalCount;
    if (S.length >= 3 && minority > 0 && minority <= this.devMax
      && ranked.slice(1).every(([, c]) => c === 1)) {
      return this.constantWithDeviations(row, key, slot, S, modal, rawOfValue);
    }
    if (counts.size <= this.p.smallSetMax && modalCount >= 2) {
      return this.defaultSlot(plan, key, slot, S, values, modal, false);
    }
    return this.siteSlot(plan, key, slot, S, values, false);
  }

  private constant(row: TemplateRow, key: string, slot: string, value: string, raw: string, S: number[]): SlotPlan {
    const existing = this.existingFor(value);
    if (existing) {
      const v = this.shared(`existing|${existing.key}`, () => {
        this.names.add(existing.key);
        return this.newVar({
          name: existing.key,
          slot,
          kind: 'existing',
          level: existing.scope === 'instance' ? 'instance' : 'tenant',
          type: 'string',
          secret: false,
          label: existing.key,
          expression: null,
          defaultValue: existing.value,
          confidence: 0.8,
          evidence: [
            `Valeur identique sur les ${S.length} sites, et égale à la variable « ${existing.key} » déjà ` +
            `enregistrée au niveau ${existing.scope === 'instance' ? 'instance' : 'client'} : réutilisée plutôt que recopiée.`,
          ],
          fit: null,
          required: true,
          reusedFrom: `variable ${existing.scope} ${existing.key}`,
        });
      });
      v.uses.push(this.useOf(row, key));
      return { kind: 'var', v, override: null };
    }
    return { kind: 'constant', raw };
  }

  private existingFor(value: string): ExistingValue | null {
    // Only a value distinctive enough to be THAT variable: a host or domain
    // name, an address, or a long string. A short word ("orange") is equal to
    // a stored default by coincidence as often as by design — and a catalogue
    // line rewritten onto the default profile is a wrong template.
    if (!/[A-Za-z]/.test(value) || !(/[.@:/]/.test(value) || value.length >= 12)) return null;
    const hits = (this.input.existingValues ?? []).filter((x) => x.value === value
      && !ROLE_NAMES.has(x.key) && !NJK_RESERVED.has(x.key));
    const keys = new Set(hits.map((h) => h.key));
    if (keys.size !== 1) return null;
    // The narrowest scope wins, as in the resolver.
    const order = { tenant: 0, global: 1, instance: 2 } as const;
    return [...hits].sort((a, b) => order[a.scope] - order[b.scope])[0];
  }

  private constantWithDeviations(
    row: TemplateRow, key: string, slot: string, S: number[], modal: string | null,
    rawOfValue: (v: string) => string,
  ): SlotPlan {
    for (const s of S) {
      const v = propValue(row.members.get(s)!, key) ?? null;
      if (v === modal) continue;
      this.deviate(s, modal === null ? 'extra_property' : 'value', slot, displayLine(row.members.get(s)!),
        modal === null
          ? `Propriété « ${key} » posée sur ce site seulement (« ${shortValue(v ?? '')} ») : non reprise.`
          : v === null
            ? `Propriété « ${key} » absente sur ce site ; le modèle pose « ${shortValue(modal)} ».`
            : `« ${key} » vaut « ${shortValue(v)} » sur ce site et « ${shortValue(modal)} » partout ailleurs : ` +
              'retouche locale probable, le modèle garde la valeur commune.');
    }
    if (modal === null) return { kind: 'omit' };
    return this.constant(row, key, slot, modal, rawOfValue(modal), S);
  }

  private siteSlot(plan: RowPlan, key: string, slot: string, S: number[], values: (string | null)[], forced: boolean): SlotPlan {
    const row = plan.row;
    const optional = values.some((v) => v === null);
    const vector = S.map((s, i) => `${s}=${values[i] ?? ''}`).join('\u0001');
    const distinct = new Set(values).size;
    const v = this.shared(`site|${vector}`, () => {
      const spec = this.newVar({
        name: this.claim(`${this.rowBase(row)}_${key}`),
        slot,
        kind: 'site',
        level: 'site',
        type: 'string',
        secret: false,
        label: `${menuShortName(row.path)} ${this.rowTag(row)} — ${key}`.replace(/\s+/g, ' ').trim(),
        expression: null,
        defaultValue: optional ? '' : null,
        confidence: forced ? 1 : distinct / S.length,
        evidence: [
          forced
            ? 'Valeur par site imposée par l\'opérateur.'
            : `Valeur propre à chaque site, relevée dans sa dernière configuration ` +
              `(${distinct} valeurs distinctes sur ${S.length} sites) ; aucune formule ` +
              '(code site, numéro de site, LAN) ne la reproduit.',
        ],
        fit: null,
        required: !optional,
      });
      S.forEach((s, i) => spec.perSite.set(s, values[i] ?? ''));
      spec.probe = this.probeFor(row, key, false);
      return spec;
    });
    v.uses.push(this.useOf(row, key));
    return optional ? { kind: 'optional', v } : { kind: 'var', v, override: null };
  }

  private defaultSlot(
    plan: RowPlan, key: string, slot: string, S: number[], values: (string | null)[],
    modal: string | null, forced: boolean,
  ): SlotPlan {
    const row = plan.row;
    const def = modal ?? '';
    const exceptions: Array<[number, string]> = [];
    S.forEach((s, i) => { if ((values[i] ?? '') !== def) exceptions.push([s, values[i] ?? '']); });
    const optional = values.some((v) => v === null);
    const key2 = `default|${def}|${exceptions.map(([s, x]) => `${s}=${x}`).join('\u0001')}`;
    const v = this.shared(key2, () => {
      const hist = new Map<string, number>();
      for (const [, x] of exceptions) hist.set(x, (hist.get(x) ?? 0) + 1);
      const histText = [...hist.entries()].sort((a, b) => b[1] - a[1])
        .map(([x, c]) => `${x === '' ? '(absente)' : `« ${shortValue(x)} »`} ×${c}`).join(', ');
      const spec = this.newVar({
        name: this.claim(`${this.rowBase(row)}_${key}`),
        slot,
        kind: 'default_exceptions',
        level: 'site',
        type: 'string',
        secret: false,
        label: `${menuShortName(row.path)} ${this.rowTag(row)} — ${key}`.replace(/\s+/g, ' ').trim(),
        expression: null,
        defaultValue: def,
        confidence: (S.length - exceptions.length) / S.length,
        evidence: [
          (forced ? 'Règle « valeur commune + exceptions » imposée par l\'opérateur. ' : '') +
          `Valeur commune ${def === '' ? '(propriété absente)' : `« ${shortValue(def)} »`} sur ` +
          `${pct(S.length - exceptions.length, S.length)} sites ; ${exceptions.length} site(s) diffèrent ` +
          `(${histText}) et reçoivent une valeur de site.`,
        ],
        fit: null,
        required: false,
      });
      for (const [s, x] of exceptions) spec.perSite.set(s, x);
      spec.probe = this.probeFor(row, key, false);
      return spec;
    });
    v.uses.push(this.useOf(row, key));
    return optional || def === '' ? { kind: 'optional', v } : { kind: 'var', v, override: null };
  }

  /** The formula families, best fit first; null when none is worth keeping. */
  private formulaSlot(plan: RowPlan, key: string, slot: string, S: number[], values: string[]): SlotPlan | null {
    const row = plan.row;
    const facts = S.map((s) => this.sites[s].facts);
    const isIdentity = row.path === '/system/identity' && key === 'name';
    const isMgmtUser = plan.role === 'mgmt' && key === 'user';
    const allocatorRole = isIdentity ? 'system_identity' : isMgmtUser ? 'ppp_username' : null;

    type Candidate =
      | { family: 'lan'; fits: number[]; parts: LanPart[]; source: string }
      | { family: 'text'; fits: number[]; pattern: TextPattern }
      | { family: 'address'; fits: number[]; source: string };
    const candidates: Candidate[] = [];
    if (this.lanAnchor !== null && !allocatorRole) {
      const lf = findLanRelation(values, S.map((s) => this.sites[s].lan));
      if (lf) candidates.push({ family: 'lan', fits: lf.fits, parts: lf.formula.parts, source: lf.formula.source });
    }
    const tf = findTextPattern(values, facts);
    if (tf && (allocatorRole ? !tf.formula.usesLan : tf.formula.inline || tf.formula.loginGrammar)) {
      candidates.push({ family: 'text', fits: tf.fits, pattern: tf.formula });
    }
    if (!allocatorRole) {
      const af = findAddressFormula(values, facts);
      if (af) candidates.push({ family: 'address', fits: af.fits, source: af.formula.source });
    }
    if (candidates.length === 0) return null;
    const best = candidates.reduce((a, b) => (b.fits.length > a.fits.length ? b : a));
    const misfits = S.map((s, i) => [s, i] as const).filter(([, i]) => !best.fits.includes(i));
    const total = S.length;
    const pure = misfits.length === 0;
    const asDeviation = !pure && total >= 3 && misfits.length <= this.devMax && !allocatorRole;
    const withExceptions = !pure && !asDeviation
      && best.fits.length >= Math.max(3, Math.ceil(this.p.formulaMinFit * total));
    if (!pure && !asDeviation && !withExceptions && !(allocatorRole && best.fits.length >= Math.max(2, Math.ceil(this.p.formulaMinFit * total)))) {
      return null;
    }
    const fitText = `vérifiée sur ${pct(best.fits.length, total)} sites`;
    const examples = best.fits.slice(0, 2).map((i) => `${this.siteLabel(S[i])} → ${shortValue(values[i])}`).join(' ; ');

    if (asDeviation) {
      for (const [s, i] of misfits) {
        this.deviate(s, 'value', slot, displayLine(row.members.get(s)!),
          `« ${key} » vaut « ${shortValue(values[i])} » ici, la règle de ${pct(best.fits.length, total)} ` +
          'autres sites donnerait une autre valeur : retouche locale probable, le modèle garde la règle.');
      }
    }
    const misfitValues = withExceptions || (allocatorRole && !pure) ? misfits : [];

    // ── allocator-owned values: login and identity ───────────────────────────
    if (allocatorRole && best.family === 'text') {
      const pattern = best.pattern;
      const v = this.shared(`role|${allocatorRole}`, () => {
        this.names.add(allocatorRole);
        const recordedKey = allocatorRole === 'ppp_username' ? 'pppUsername' : 'systemIdentity';
        let agree = 0;
        let rec = 0;
        S.forEach((s, i) => {
          const r = this.sites[s].input.recorded[recordedKey];
          if (!r) return;
          rec++;
          if (r === values[i]) agree++;
        });
        const evidence = [
          `${allocatorRole === 'ppp_username' ? 'Modèle de login PPP' : "Modèle d'identité système"} ` +
          `« ${pattern.source} », ${fitText} par le moteur de l'allocateur (ex. ${examples}).`,
        ];
        if (rec > 0) evidence.push(`Identique à la valeur enregistrée dans ObliWAN pour ${pct(agree, rec)} sites.`);
        if (misfitValues.length > 0) {
          evidence.push(`${misfitValues.length} site(s) ne suivent pas le modèle : l'allocateur doit garder leur valeur adoptée.`);
        }
        if (!pattern.loginGrammar) {
          evidence.push('Attention : ce motif contient des caractères que le modèle de login de l\'allocateur refuse.');
        }
        const spec = this.newVar({
          name: allocatorRole,
          slot,
          kind: 'formula',
          level: 'computed',
          type: 'string',
          secret: false,
          label: allocatorRole === 'ppp_username' ? `Login PPP de management (${MANAGEMENT_TUNNEL_NAME})` : 'Identité système',
          expression: pattern.source,
          defaultValue: null,
          confidence: best.fits.length / total,
          evidence,
          fit: { matched: best.fits.length, total },
          required: true,
        });
        const fitSet = new Set(best.fits.map((i) => S[i]));
        const observed = new Map(S.map((s, i) => [s, values[i]] as const));
        spec.computed = (s) => (fitSet.has(s) ? evaluateTextPattern(pattern, this.sites[s].facts) : observed.get(s) ?? null);
        for (const [s, i] of misfitValues) {
          spec.perSite.set(s, values[i]);
          const st = this.sites[s].input;
          this.policy.adopted.push({ key: allocatorRole, siteId: st.siteId, siteCode: st.site?.code ?? null, value: values[i] });
        }
        if (allocatorRole === 'ppp_username') this.policy.pppLoginTemplate = pattern.source;
        else this.policy.systemIdentityTemplate = pattern.source;
        return spec;
      });
      v.uses.push(this.useOf(row, key));
      return { kind: 'var', v, override: null };
    }
    if (allocatorRole) return null;

    const override = misfitValues.length > 0 ? this.overrideVar(plan, key, slot, misfitValues.map(([s, i]) => [s, values[i]] as [number, string]), best.fits.length, total) : null;

    if (best.family === 'lan') {
      const lanVar = this.ensureLanVar();
      lanVar.uses.push(this.useOf(row, key));
      if (this.lanAnchor === row.key && key === 'address') {
        lanVar.evidence.push(`Adresse de l'interface LAN : « ${best.source} », ${fitText}.`);
      }
      return { kind: 'lan', parts: best.parts, override };
    }
    if (best.family === 'text' && best.pattern.inline) {
      const use = `${this.useOf(row, key)} (motif « ${best.pattern.source} », ${fitText})`;
      if (best.pattern.segments.some((x) => x.kind === 'ph' && x.name === 'site.code')) {
        this.ensureSiteCodeVar().uses.push(use);
      }
      if (best.pattern.usesLan) this.ensureLanVar().uses.push(use);
      return { kind: 'code', pattern: best.pattern, override };
    }
    // A derived value of the allocator policy (`derived: { key: expression }`).
    const expression = best.family === 'text' ? best.pattern.source : best.source;
    const v = this.shared(`derived|${expression}`, () => {
      const spec = this.newVar({
        name: this.claim(`${this.rowBase(row)}_${key}`),
        slot,
        kind: 'formula',
        level: 'computed',
        type: 'string',
        secret: false,
        label: `${menuShortName(row.path)} ${this.rowTag(row)} — ${key}`.replace(/\s+/g, ' ').trim(),
        expression,
        defaultValue: null,
        confidence: best.fits.length / total,
        evidence: [
          `${best.family === 'text' ? 'Motif' : "Formule d'adresse"} « ${expression} » sur le site, ` +
          `${fitText} par l'évaluateur de l'allocateur (ex. ${examples}). Valeur dérivée de la politique ` +
          "d'allocation (calculée par ObliWAN, jamais saisie).",
        ],
        fit: { matched: best.fits.length, total },
        required: true,
      });
      const fitSet = new Set(best.fits.map((i) => S[i]));
      const observed = new Map(S.map((s, i) => [s, values[i]] as const));
      if (best.family === 'text') {
        const pattern = best.pattern;
        spec.computed = (s) => evaluateTextPattern(pattern, this.sites[s].facts) ?? (fitSet.has(s) ? null : observed.get(s) ?? null);
      } else {
        spec.computed = (s) => evaluateAddressFormula(expression, this.sites[s].facts.id) ?? observed.get(s) ?? null;
      }
      this.policy.derived[spec.name] = expression;
      return spec;
    });
    v.uses.push(this.useOf(row, key));
    return { kind: 'var', v, override };
  }

  private overrideVar(plan: RowPlan, key: string, slot: string, misfits: Array<[number, string]>, fits: number, total: number): VarSpec {
    const row = plan.row;
    const spec = this.newVar({
      name: this.claim(`${this.rowBase(row)}_${key}_site`),
      slot: `${slot}#exception`,
      kind: 'site',
      level: 'site',
      type: 'string',
      secret: false,
      label: `${menuShortName(row.path)} ${this.rowTag(row)} — ${key} (exception de site)`.replace(/\s+/g, ' ').trim(),
      expression: null,
      defaultValue: null,
      confidence: fits / total,
      evidence: [
        `La règle reproduit ${pct(fits, total)} sites ; ${misfits.length} site(s) gardent leur propre valeur ` +
        '(exception posée au niveau du site, la règle s\'applique partout ailleurs).',
      ],
      fit: null,
      required: false,
    });
    for (const [s, x] of misfits) spec.perSite.set(s, x);
    spec.uses.push(this.useOf(row, key));
    spec.overrides = `${row.key}#${key}`;
    return spec;
  }

  // ── 4. secrets ────────────────────────────────────────────────────────────

  private planSecrets(): void {
    for (const plan of this.plans) {
      if (plan.mode === 'excluded' || plan.row.opaqueText !== null) continue;
      const row = plan.row;
      if (plan.wan === 'pppoe') {
        // The block's own secret, per store, never valued.
        const v = this.wanVars.get(WAN1_KEYS.pppoePassword)!;
        v.uses.push(this.useOf(row, 'password'));
        plan.secrets.push({ key: 'password', optional: false, v });
        continue;
      }
      const members = [...row.members.entries()];
      const keys: Array<{ key: string; owner: string | null; optional: boolean }> = [];
      for (const c of SECRET_COMPANIONS) {
        if (c.path !== row.path) continue;
        const holds = members.filter(([, e]) => c.when(e)).length;
        if (holds * 2 > members.length) keys.push({ key: c.key, owner: c.owner, optional: c.optional === true });
      }
      // A sensitive property the export carried by NAME (an export printing
      // `password=""`): declared too, its value was dropped by the funnel.
      for (const [, e] of members) {
        for (const k of e.secretKeys) if (!keys.some((x) => x.key === k)) keys.push({ key: k, owner: null, optional: false });
      }
      for (const { key, owner, optional } of keys) {
        plan.secrets.push({ key, optional, v: this.secretVar(plan, key, owner, optional) });
      }
    }
  }

  private secretVar(plan: RowPlan, key: string, owner: string | null, optional: boolean): VarSpec {
    const row = plan.row;
    const slot = `${row.key}#${key}`;
    const ownerVector = owner === null ? null : this.sites.map((_, s) => {
      const e = row.members.get(s);
      return e ? propValue(e, owner) ?? '' : null;
    });
    const ownerValues = ownerVector ? new Set(ownerVector.filter((x): x is string => x !== null)) : null;
    const ownerConstant = ownerValues !== null && ownerValues.size === 1;
    const ov = this.overrideFor(slot);
    let level: ExtrapolatedLevel;
    const evidence: string[] = [
      `Secret : « ${key} » n'apparaît jamais dans un export expurgé. Sa valeur n'est ni lue ni ` +
      'proposée : elle se saisit dans le coffre (variables), ou se relit par l\'analyse d\'infrastructure si ' +
      'la variable est de niveau site.',
    ];
    let name: string;
    if (plan.role === 'mgmt' && key === 'password') {
      name = SHARED_PPP_PASSWORD_KEY;
      level = 'instance';
      evidence.push('Tunnel de management : mot de passe PPP partagé de l\'installation (mode « shared » de l\'allocateur).');
    } else {
      name = `${this.rowBase(row)}_${key}`;
      if (row.path === '/interface/wireguard') level = 'site';
      else if (ownerVector === null) level = 'tenant';
      else level = ownerConstant ? 'tenant' : 'site';
      evidence.push(
        ownerVector === null
          ? 'Niveau proposé : client (aucun indice de partage).'
          : ownerConstant
            ? `Niveau proposé : client — « ${owner} » est identique sur tous les sites, le secret l'est sans doute aussi.`
            : `Niveau proposé : site — « ${owner} » diffère d'un site à l'autre.`,
      );
    }
    if (optional) {
      evidence.push(
        "L'export ne dit pas si cette valeur est posée (elle est masquée dans tous les cas) : la variable " +
        "est FACULTATIVE — sans valeur au coffre, la propriété n'est pas écrite.",
      );
    }
    if (ov?.secretLevel) {
      level = ov.secretLevel;
      evidence.push(`Niveau imposé par l'opérateur : ${ov.secretLevel}.`);
    }
    const unifyKey = name === SHARED_PPP_PASSWORD_KEY
      ? `secret|${name}`
      : `secret|${key}|${level}|${ownerVector ? ownerVector.join('\u0001') : row.key}`;
    const v = this.shared(unifyKey, () => {
      let claimed = name;
      if (name === SHARED_PPP_PASSWORD_KEY) this.names.add(name);
      else claimed = this.claim(name);
      const spec = this.newVar({
        name: claimed,
        slot,
        kind: 'secret',
        level,
        type: 'string',
        secret: true,
        label: `${menuShortName(row.path)} ${this.rowTag(row)} — ${key} (secret)`.replace(/\s+/g, ' ').trim(),
        expression: null,
        defaultValue: null,
        confidence: 0.6,
        evidence,
        fit: null,
        required: !optional,
      });
      if (level === 'site') spec.probe = this.probeFor(row, key, true);
      return spec;
    });
    v.uses.push(this.useOf(row, key));
    return v;
  }

  // ── 5. probes (the infra analysis re-reads a site variable) ──────────────

  private probeFor(row: TemplateRow, key: string, secret: boolean): Record<string, unknown> | null {
    const spec = DISCOVER_MENUS[row.path];
    if (!spec || !DISCOVER_PROPERTY_RE.test(key)) return null;
    const sensitive = isSensitiveDiscoverProperty(row.path, key);
    if (sensitive !== secret) return null;
    const probe: Record<string, unknown> = { menu: row.path };
    if (spec.kind === 'list') {
      const where: Record<string, string> = {};
      const members = [...row.members.values()];
      if (row.selectorCanon) {
        for (const kv of row.selectorCanon.split(' ')) {
          const eq = kv.indexOf('=');
          if (eq > 0) where[kv.slice(0, eq)] = kv.slice(eq + 1);
        }
      } else {
        const name = propValue(row.ref, 'name');
        if (name !== undefined && members.every((e) => propValue(e, 'name') === name)) where.name = name;
        else {
          for (const k of ['interface', 'default-name', 'comment', 'list', 'chain']) {
            if (k === key || Object.keys(where).length >= 2) continue;
            const v = propValue(row.ref, k);
            if (v !== undefined && v.length <= 128 && members.every((e) => propValue(e, k) === v)) where[k] = v;
          }
        }
      }
      if (Object.keys(where).length === 0) return null;
      if (Object.keys(where).some((k) => isSensitiveDiscoverProperty(row.path, k) || !DISCOVER_PROPERTY_RE.test(k))) return null;
      probe.where = where;
    }
    probe.property = key;
    if (sensitive) probe.sensitive = true;
    return probe;
  }

  /** An existing template's probe at the same place names the variable. */
  private adoptExistingNames(): void {
    const probes = this.input.existingProbes ?? [];
    if (probes.length === 0) return;
    const sig = (menu: string, where: Record<string, unknown> | undefined, property: string): string =>
      `${menu}|${JSON.stringify(Object.entries(where ?? {}).map(([k, v]) => [k, String(v)]).sort())}|${property}`;
    const index = new Map<string, ExistingProbe>();
    for (const p of probes) index.set(sig(p.menu, p.where, p.property), p);
    for (const v of this.vars) {
      if (!v.probe || ROLE_NAMES.has(v.name) || v.standard) continue;
      const hit = index.get(sig(String(v.probe.menu), v.probe.where as Record<string, unknown> | undefined, String(v.probe.property)));
      if (!hit || hit.key === v.name) continue;
      // The key lands in the body as an identifier: it must be one.
      if (!/^[a-z][a-zA-Z0-9_]{0,119}$/.test(hit.key) || NJK_RESERVED.has(hit.key) || ROLE_NAMES.has(hit.key)) continue;
      if (this.names.has(hit.key)) continue;
      this.names.delete(v.name);
      this.names.add(hit.key);
      v.evidence.push(`Nom repris de la sonde « ${hit.key} » du modèle « ${hit.source} » (même menu, même élément, même propriété).`);
      v.reusedFrom = `${hit.source} → ${hit.key}`;
      if (hit.label) v.label = hit.label;
      v.name = hit.key;
    }
  }

  /**
   * A variable is REQUIRED only when a line every site renders uses it. One
   * used only inside a variant (`{% if flag %}`) must not be demanded of the
   * sites that do not carry the variant — the resolver would refuse their
   * render for a value the body never reads there.
   */
  private settleRequired(): void {
    const used = new Set<VarSpec>();
    for (const plan of this.plans) {
      if (plan.mode !== 'always') continue;
      for (const sp of plan.slots.values()) {
        if (sp.kind === 'var' || sp.kind === 'optional') used.add(sp.v);
        if ((sp.kind === 'var' || sp.kind === 'lan' || sp.kind === 'code') && sp.override) used.add(sp.override);
        if (sp.kind === 'lan' && this.lanVar) used.add(this.lanVar);
        if (sp.kind === 'code') {
          for (const seg of sp.pattern.segments) {
            if (seg.kind !== 'ph') continue;
            if (seg.name === 'site.code' && this.siteCodeVar) used.add(this.siteCodeVar);
            if ((seg.name === 'lan' || seg.name === 'lan.network') && this.lanVar) used.add(this.lanVar);
          }
        }
      }
      for (const s of plan.secrets) used.add(s.v);
    }
    for (const v of this.vars) {
      if (v.required && !used.has(v)) {
        v.required = false;
        v.evidence.push('Utilisée seulement dans une variante : non obligatoire pour les sites qui ne la portent pas.');
      }
    }
  }

  // ── 6. the body ───────────────────────────────────────────────────────────

  private renderBody(): { body: string; lineCount: number } {
    const lines: string[] = [];
    const st = this.input;
    // Inside a Nunjucks comment: nothing may close it early.
    const safe = (x: string): string => x.replace(/[{}#%]/g, '');
    lines.push(
      `{#- ${safe(st.label)} — modèle PROPOSÉ par l'extrapolateur ObliWAN${st.runLabel ? ` (${safe(st.runLabel)})` : ''},`,
      `    déduit de ${this.n} routeur(s) ; à relire avant publication. Les secrets ne sont jamais lus :`,
      '    ils se saisissent dans le coffre. -#}',
    );
    if (this.wan1?.emit) lines.push(...wan1BodyPreamble(this.wan1.vlan, this.wan1.netwatch));
    let lineCount = 0;
    for (const block of this.blocks) {
      const plans = this.plans.filter((pl) => pl.block === block && pl.mode !== 'excluded');
      if (plans.length === 0) continue;
      // A menu whose every line is under the same WAN1 condition is written
      // under it, header included (`/ip dhcp-client` in static mode).
      const blockCond = plans.every((pl) => pl.flag === null && pl.cond !== null)
        && new Set(plans.map((pl) => pl.cond)).size === 1 ? plans[0].cond : null;
      if (blockCond !== null) lines.push(`{% if ${blockCond} -%}`);
      lines.push(literal(menuHeader(block.path)));
      for (const plan of plans) {
        const text = this.rowLine(plan);
        lineCount++;
        if (plan.flag) {
          lines.push(`{% if ${plan.flag.name} -%}`, text, '{% endif -%}');
        } else if (plan.cond !== null && blockCond === null) {
          lines.push(`{% if ${plan.cond} -%}`, text, '{% endif -%}');
        } else {
          lines.push(text);
        }
      }
      if (blockCond !== null) lines.push('{% endif -%}');
    }
    return { body: lines.join('\n') + '\n', lineCount };
  }

  /** ` key=value` for one slot ('' when the slot writes nothing). */
  private slotText(key: string, sp: SlotPlan): string {
    switch (sp.kind) {
      case 'omit': return '';
      case 'constant': return ` ${key}=${literal(sp.raw)}`;
      case 'var': return ` ${key}=${withOverride(sp.override, `{{ ${sp.v.name} }}`)}`;
      case 'optional': return `{% if ${sp.v.name} %} ${key}={{ ${sp.v.name} }}{% endif %}`;
      case 'lan': return ` ${key}=${withOverride(sp.override, lanExpr(sp.parts))}`;
      case 'code': return ` ${key}=${withOverride(sp.override, codeExpr(sp.pattern))}`;
      case 'expr': return ` ${key}=${sp.text}`;
      case 'split': {
        const head = sp.cases.map((c, i) => `{% ${i === 0 ? 'if' : 'elif'} ${c.cond} %} ${key}=${c.text}`).join('');
        return `${head}{% else %}${this.slotText(key, sp.rest)}{% endif %}`;
      }
    }
  }

  private rowLine(plan: RowPlan): string {
    const row = plan.row;
    if (row.opaqueText !== null) return literal(row.opaqueText);
    let out = row.verb;
    if (row.selectorRaw) out += ` ${literal(row.selectorRaw)}`;
    for (const p of row.positional) out += ` ${literal(p)}`;
    for (const rawKey of row.keyOrder) {
      const sp = plan.slots.get(rawKey);
      if (!sp) continue;
      // The property NAME is router text too: neutralised like any literal.
      out += this.slotText(literal(rawKey), sp);
    }
    for (const s of plan.secrets) {
      const key = literal(s.key);
      out += s.optional
        ? `{% if ${s.v.name} is defined %} ${key}={{ ${s.v.name} }}{% endif %}`
        : ` ${key}={{ ${s.v.name} }}`;
    }
    return out;
  }

  // ── 7. var_schema ─────────────────────────────────────────────────────────

  private variablesOut(): ExtrapolatedVariable[] {
    return this.vars.map((v) => ({
      name: v.name,
      slot: v.slot,
      kind: v.kind,
      level: v.level,
      type: v.type,
      secret: v.secret,
      label: v.label.slice(0, 200),
      description: this.describe(v),
      expression: v.expression,
      defaultValue: v.secret ? null : v.defaultValue,
      confidence: Math.round(Math.max(0, Math.min(1, v.confidence)) * 1000) / 1000,
      evidence: v.evidence,
      uses: [...new Set(v.uses)],
      siteValues: v.secret ? [] : [...v.perSite.entries()]
        .sort((a, b) => a[0] - b[0])
        .map(([s, x]) => this.siteValue(s, typeof x === 'boolean' ? (x ? 'true' : 'false') : x)),
      fit: v.fit,
      probe: v.probe,
      reusedFrom: v.reusedFrom,
    }));
  }

  private describe(v: VarSpec): string {
    const rule: Record<ExtrapolatedRuleKind, string> = {
      formula: `Calculé par ObliWAN${v.expression ? ` (« ${v.expression} »)` : ''}.`,
      site_code: 'Code du site.',
      lan: `LAN du site, fourni par l'allocateur${v.expression ? ` (formule « ${v.expression} »)` : ' (LAN enregistré)'}.`,
      default_exceptions: 'Valeur commune, avec des exceptions de site.',
      site: v.overrides ? 'Exception de site à une règle calculée.' : 'Valeur propre à chaque site.',
      secret: 'Secret (coffre) : jamais lu, jamais proposé.',
      presence: 'Variante : lignes présentes sur une partie des sites.',
      existing: 'Variable déjà enregistrée, réutilisée.',
    };
    const uses = [...new Set(v.uses)];
    return [
      v.standard && v.description
        ? `Proposé par l'extrapolateur (bloc WAN1 standard). ${v.description}`
        : `Proposé par l'extrapolateur. ${rule[v.kind]}`,
      ...v.evidence,
      uses.length > 0 ? `Utilisé dans : ${uses.slice(0, 6).join(' ; ')}${uses.length > 6 ? ` (+${uses.length - 6})` : ''}.` : '',
    ].filter((x) => x !== '').join(' ').slice(0, 4000);
  }

  private varSchema(variables: ExtrapolatedVariable[]): Record<string, unknown> {
    const properties: Record<string, Record<string, unknown>> = {};
    const required: string[] = [];
    for (const v of variables) {
      const spec = this.vars.find((x) => x.name === v.name)!;
      const p: Record<string, unknown> = {
        type: v.type,
        'x-obliwan-level': v.level,
        'x-obliwan-label': v.label,
        description: v.description,
      };
      if (v.secret) p['x-obliwan-secret'] = true;
      if (!v.secret && v.level !== 'computed' && v.defaultValue !== null && v.kind !== 'existing') {
        p.default = v.defaultValue;
      }
      if (v.secret) p.minLength = 1;
      if (v.expression && v.level === 'computed') p['x-obliwan-formula'] = v.expression;
      if (spec.standard && spec.schemaExtra) Object.assign(p, spec.schemaExtra);
      if (v.probe && v.level === 'site') p[DISCOVER_KEYWORD] = v.probe;
      properties[v.name] = p;
      if (spec.required) required.push(v.name);
    }
    // A probe the grammar refuses is dropped, never shipped broken. So is any
    // probe that is not a PROPERTY read: a presence test (`present`, with or
    // without `absent`) states what a match — or an absence — MEANS, which is
    // an operator's judgement, never something a fleet's exports can show
    // (`probeFor` builds property reads only; this keeps it so). ONE
    // exception, by name and by content: the standard WAN1 block's own probes
    // (wan1.ts), which the operator wrote and the extrapolator only copies —
    // a probe that differs from them by one key is dropped like any other.
    const declared = (k: string): boolean => Object.prototype.hasOwnProperty.call(properties, k);
    for (const [key, p] of Object.entries(properties)) {
      if (!(DISCOVER_KEYWORD in p)) continue;
      const probe = p[DISCOVER_KEYWORD] as Record<string, unknown> | null;
      const propertyRead = !!probe && typeof probe === 'object' && typeof probe.property === 'string'
        && !('present' in probe) && !('absent' in probe)
        // Nor a CONDITIONED read (`unless`, `single`, `else`): a condition is
        // an operator's judgement too.
        && !('unless' in probe) && !('single' in probe) && !('else' in probe);
      const standard = this.wanVars.has(key) && isStandardWan1Probe(key, probe);
      if (!(propertyRead || standard)
        || discoverProbeProblems(p[DISCOVER_KEYWORD], { key, property: p, declared }).length > 0) {
        delete p[DISCOVER_KEYWORD];
        const v = variables.find((x) => x.name === key);
        if (v) v.probe = null;
      }
    }
    return { type: 'object', properties, required };
  }

  // ── 8. contexts ───────────────────────────────────────────────────────────

  /**
   * The REDACTED context of each site. A site variable a site has no value for
   * (the site lacks the line — a `missing_line` deviation the template still
   * renders) gets the most common value FOR THE PROOF ONLY, so one deleted line
   * costs that line in the score instead of the whole render. It is never
   * proposed as that site's value.
   */
  private contexts(): Array<Record<string, unknown>> {
    const fallback = new Map<VarSpec, string | boolean>();
    for (const v of this.vars) {
      if (v.kind !== 'site' || v.overrides !== null || v.perSite.size === 0) continue;
      const hist = new Map<string | boolean, number>();
      for (const x of v.perSite.values()) hist.set(x, (hist.get(x) ?? 0) + 1);
      fallback.set(v, [...hist.entries()].sort((a, b) => b[1] - a[1])[0][0]);
    }
    return this.sites.map((_, s) => {
      const ctx: Record<string, unknown> = {};
      for (const v of this.vars) {
        let value: string | boolean | null | undefined;
        if (v.standard) {
          // What the resolver hands the render: the site's value, else the
          // schema default — never another site's value.
          value = v.kind === 'secret'
            ? secretPlaceholder(v.name)
            : v.perSite.has(s) ? v.perSite.get(s) : v.defaultValue;
          if (value !== null && value !== undefined) ctx[v.name] = value;
          continue;
        }
        switch (v.kind) {
          case 'secret': value = secretPlaceholder(v.name); break;
          case 'formula':
          case 'lan': value = v.computed ? v.computed(s) : null; break;
          case 'existing': value = v.defaultValue; break;
          case 'default_exceptions':
          case 'presence': value = v.perSite.has(s) ? v.perSite.get(s) : v.defaultValue; break;
          case 'site':
          case 'site_code': value = v.perSite.has(s) ? v.perSite.get(s) : fallback.get(v); break;
        }
        if (value !== null && value !== undefined) ctx[v.name] = value;
      }
      return ctx;
    });
  }

  // ── run ───────────────────────────────────────────────────────────────────

  build(): ClusterDraft {
    if (this.n === 0) throw new Error('a cluster needs at least one site');
    const refused = this.sites.reduce((a, st) => a + st.parsed.refusedSecretValues, 0);
    if (refused > 0) {
      this.warnings.push(
        `${refused} valeur(s) de propriété sensible présentes dans les exports ont été écartées sans être lues ` +
        '(un export devrait être expurgé).',
      );
    }
    let ref = this.input.referenceDeviceId === null
      ? -1
      : this.sites.findIndex((st) => st.input.deviceId === this.input.referenceDeviceId);
    if (ref < 0) {
      const bySize = this.sites.map((st, i) => [st.parsed.entries.length, i] as const).sort((a, b) => a[0] - b[0]);
      ref = bySize[Math.floor(bySize.length / 2)][1];
    }
    const order = [ref, ...this.sites.map((_, i) => i).filter((i) => i !== ref)
      .sort((a, b) => this.sites[a].input.deviceId - this.sites[b].input.deviceId)];
    this.order = order;
    // The standard WAN1 block (wan1.ts). Not emitted — every pure-DHCP
    // cluster — and nothing below differs from what it always was.
    this.wan1 = planWan1Cluster(this.sites.map((st) => st.parsed.entries));
    const pulled = this.wan1.pulled;
    this.blocks = alignSites(
      this.sites.map((st, s) => {
        const out = pulled.get(s);
        return out ? st.parsed.entries.filter((e) => !out.includes(e)) : st.parsed.entries;
      }),
      order,
    );
    if (this.wan1.emit) {
      this.createWan1Vars();
      this.regroupWan1Rows();
      this.synthesizeWan1Rows();
      this.reportExcludedWan1();
    }
    this.planRows();
    this.detectLan();
    this.planSlots();
    this.planSecrets();
    this.adoptExistingNames();
    this.settleRequired();
    for (const plan of this.plans) {
      if (plan.mode === 'excluded') continue;
      const text = plan.row.opaqueText ?? displayLine(plan.row.ref);
      if (/\{\{|\{%|\}\}|%\}/.test(text)) {
        for (const s of plan.row.members.keys()) {
          this.deviate(s, 'untemplatable', plan.row.key, displayLine(plan.row.members.get(s)!),
            'La ligne contient « {{ », « }} », « {% » ou « %} » : le modèle l\'écrit avec une espace ' +
            '(« } } ») et le rendu ne la reproduit donc pas à l\'identique. À vérifier.');
        }
      }
    }
    if (Object.keys(this.policy.derived).length > 20) {
      this.warnings.push(
        `${Object.keys(this.policy.derived).length} valeurs dérivées proposées : la politique d'allocation en ` +
        'accepte 20 au plus — à regrouper avant de les reporter.',
      );
    }
    const wanWarning = this.wan1Warning();
    if (wanWarning !== null) this.warnings.push(wanWarning);
    const { body, lineCount } = this.renderBody();
    const variables = this.variablesOut();
    const varSchema = this.varSchema(variables);
    this.deviations.sort((a, b) => a.deviceId - b.deviceId || a.slot.localeCompare(b.slot));
    return {
      label: this.input.label,
      clusterIndex: this.input.clusterIndex,
      body,
      bodySha256: createHash('sha256').update(body, 'utf8').digest('hex'),
      varSchema,
      variables,
      policy: this.policy,
      deviations: this.deviations,
      warnings: this.warnings,
      lineCount,
      contexts: this.contexts(),
      parsed: this.sites.map((st) => st.parsed),
      refusedSecretValues: refused,
      wan1: this.wan1?.summary ?? null,
    };
  }

  // ── WAN1: the standard block (wan1.ts) ───────────────────────────────────

  /** The entry the row keeps as its reference: the first site in fold order. */
  private refOf(members: ReadonlyMap<number, ExportEntry>): ExportEntry {
    for (const s of this.order) {
      const e = members.get(s);
      if (e) return e;
    }
    return members.values().next().value as ExportEntry;
  }

  private keyOrderOf(members: ReadonlyMap<number, ExportEntry>): string[] {
    const keys: string[] = [];
    for (const s of this.order) {
      const e = members.get(s);
      if (!e) continue;
      for (const p of e.props) if (!keys.includes(p.key)) keys.push(p.key);
    }
    return keys;
  }

  /** The six standard variables (seven with a VLAN), valued from the routers
   *  of the block. The PPPoE password is declared and never valued. */
  private createWan1Vars(): void {
    const plan = this.wan1!;
    const sum = plan.summary!;
    const K = WAN1_KEYS;
    const probes = standardWan1Probes();
    const inBlock = plan.shapes.filter((x) => x !== null).length;
    const valued = (pick: (shape: NonNullable<Wan1ClusterPlan['shapes'][number]>) => string | null): Array<[number, string]> => {
      const out: Array<[number, string]> = [];
      plan.shapes.forEach((shape, s) => {
        if (!shape) return;
        const v = pick(shape);
        if (v !== null) out.push([s, v]);
      });
      return out;
    };
    const names = Object.entries(sum.pppoeNames).sort((a, b) => b[1] - a[1]).map(([k, c]) => `${k} ×${c}`).join(', ');
    const unobserved = (mode: Wan1Mode): string =>
      `Aucun routeur ${mode} dans ce profil : cette branche est écrite d'après le bloc standard des modèles, ` +
      'et le rendu de contrôle de la preuve WAN1 la vérifie sur un routeur du profil.';
    const make = (
      name: string, kind: 'site' | 'secret', label: string, description: string,
      defaultValue: string | null, schemaExtra: Record<string, unknown>, evidence: string[],
      perSite: Array<[number, string]>, probe: Record<string, unknown> | null,
    ): void => {
      this.names.add(name);
      const v: VarSpec = {
        name, slot: `wan1#${name}`, kind, level: 'site', type: 'string', secret: kind === 'secret', label,
        expression: null, defaultValue, perSite: new Map(perSite), computed: null,
        confidence: inBlock / Math.max(1, this.n), evidence, uses: [], fit: null, probe,
        reusedFrom: 'bloc WAN1 standard', required: false, overrides: null,
        standard: true, schemaExtra, description,
      };
      this.vars.push(v);
      this.wanVars.set(name, v);
    };

    const excludedText = sum.excluded.length === 0
      ? 'Aucun routeur exclu du bloc.'
      : `${sum.excluded.length} routeur(s) exclu(s) du bloc, sans valeur : ` +
        `${sum.excluded.slice(0, 8).map((x) => `${this.siteLabel(x.site)} (${x.mode ? `${x.mode} : ` : ''}${x.reason})`).join(' ; ')}` +
        `${sum.excluded.length > 8 ? ` (+${sum.excluded.length - 8})` : ''}.`;
    make(
      K.mode, 'site', 'Type de lien WAN1 (ether1)',
      `dhcp (défaut) : le client DHCP de ${WAN1_PORT} repositionne les routes ${WAN1_ROUTE_NW} et ${WAN1_ROUTE_GW}. ` +
      `pppoe : client PPPoE ${K.pppoeName} sur ${WAN1_PORT}${plan.vlan ? ` (ou sur son VLAN ${K.vlanId})` : ''}, membre de la ` +
      `liste ${WAN_LIST_NAME}, routes ${WAN1_ROUTE_NW} / ${WAN1_ROUTE_GW}${plan.netwatch ? ` et netwatch ${WAN1_NETWATCH_COMMENT}` : ''} ` +
      `désactivés, client DHCP conservé (microcode) ; exige ${K.pppoeUsername} et ${K.pppoePassword}. static : ${K.address} ` +
      `sur ${WAN1_PORT}, routes par ${K.gateway}, pas de client DHCP${plan.netwatch ? ', netwatch conservé (bascule LTE)' : ''} ; ` +
      `exige ${K.address} et une ${K.gateway} dans son réseau. Sonde « présent seulement » : un client PPPoE ACTIF sur ` +
      `${WAN1_PORT} propose pppoe ; sinon UNE adresse fixe active non dynamique sur ${WAN1_PORT}, sans client DHCP actif sur ` +
      'ce port ni client PPPoE actif sur le routeur, propose static ; une absence ne propose rien (jamais dhcp).',
      'dhcp', { enum: [...WAN1_MODES] },
      [
        `Bloc WAN1 standard relevé sur ${inBlock}/${this.n} routeurs : ${sum.counts.dhcp} dhcp, ${sum.counts.pppoe} pppoe` +
        `${names ? ` (${names}${sum.vlan > 0 ? `, dont ${sum.vlan} sur VLAN` : ''})` : ''}, ${sum.counts.static} static. ` +
        'Valeur de site posée pour chaque routeur pppoe ou static ; « dhcp » est la valeur par défaut du schéma : ' +
        'aucune valeur n\'est écrite pour un routeur dhcp.',
        excludedText,
      ],
      valued((x) => (x.mode === 'dhcp' ? null : x.mode)),
      probes[K.mode],
    );
    make(
      K.pppoeName, 'site', 'Interface PPPoE (WAN1)',
      `Lu seulement si ${K.mode} = pppoe : name= du client PPPoE et interface= de sa ligne de la liste ${WAN_LIST_NAME}. ` +
      `${PPPOE_UPLINK_NAMES.join(', ')} (liste fermée, comme le microcode les nomme), défaut ADSL. Relu par l'analyse ` +
      `sur le client ACTIF de ${WAN1_PORT} seulement.`,
      'ADSL', { enum: [...PPPOE_UPLINK_NAMES] },
      [sum.counts.pppoe > 0
        ? `Nom relevé sur chacun des ${sum.counts.pppoe} routeur(s) pppoe (${names}) ; valeur de site posée pour chacun, ADSL compris.`
        : unobserved('pppoe')],
      valued((x) => x.pppoeName),
      probes[K.pppoeName],
    );
    make(
      K.pppoeUsername, 'site', 'Login PPPoE (FAI)',
      `Lu seulement si ${K.mode} = pppoe : user= du client PPPoE (lettres, chiffres et . _ @ + / -, les logins fti/… ` +
      `existent). Relu par l'analyse sur le client ACTIF de ${WAN1_PORT}.`,
      null, { pattern: WAN1_USERNAME_PATTERN },
      [sum.counts.pppoe > 0 ? `Login relevé sur chacun des ${sum.counts.pppoe} routeur(s) pppoe.` : unobserved('pppoe')],
      valued((x) => x.pppoeUsername),
      probes[K.pppoeUsername],
    );
    make(
      K.pppoePassword, 'secret', 'Mot de passe PPPoE (FAI)',
      `Lu seulement si ${K.mode} = pppoe. Au coffre, par magasin ; l'analyse ne le lit qu'à la demande, avec un compte ` +
      'qui a la politique sensitive, et ne l\'affiche jamais.',
      null, {},
      ['Secret : l\'export expurgé ne le porte jamais. Jamais lu, jamais proposé, jamais écrit à l\'approbation.'],
      [],
      probes[K.pppoePassword],
    );
    make(
      K.address, 'site', 'Adresse fixe WAN1 (CIDR)',
      `Lu seulement si ${K.mode} = static : l'adresse fixe de ${WAN1_PORT} avec son préfixe (ex. 203.0.113.10/29), écrite ` +
      `en adresse statique sur ${WAN1_PORT}. Une adresse d'hôte : l'adresse de réseau ou de diffusion d'un /8 à /30 est ` +
      `refusée au rendu. Sonde conditionnée : l'UNIQUE adresse fixe active non dynamique de ${WAN1_PORT}, lue seulement ` +
      'sans client DHCP actif sur ce port ni client PPPoE actif sur le routeur.',
      null, { pattern: WAN1_ADDRESS_PATTERN },
      [sum.counts.static > 0 ? `Adresse relevée sur chacun des ${sum.counts.static} routeur(s) static.` : unobserved('static')],
      valued((x) => x.address),
      probes[K.address],
    );
    make(
      K.gateway, 'site', 'Passerelle fixe WAN1',
      `Lu seulement si ${K.mode} = static : gateway= des routes ${WAN1_ROUTE_NW} et ${WAN1_ROUTE_GW}, dans le réseau de ` +
      `${K.address} et différente de l'adresse du routeur (refusé au rendu sinon). Relu sur la route ${WAN1_ROUTE_GW} ` +
      'ACTIVE ; sur un magasin dhcp c\'est la passerelle que le client DHCP y a écrite, que le rendu ignore hors mode static.',
      null, { pattern: WAN1_GATEWAY_PATTERN },
      [sum.counts.static > 0
        ? `Passerelle des routes ${WAN1_ROUTE_NW} / ${WAN1_ROUTE_GW} relevée sur chacun des ${sum.counts.static} routeur(s) static.`
        : unobserved('static')],
      valued((x) => x.gateway),
      probes[K.gateway],
    );
    if (plan.vlan) {
      make(
        K.vlanId, 'site', 'VLAN du client PPPoE (WAN1)',
        `Lu seulement si ${K.mode} = pppoe : le VLAN de ${WAN1_PORT} qui porte le client PPPoE (FTTH : 832), interface ` +
        `nommée vlan<id>. Absent : le client est sur ${WAN1_PORT} lui-même. Hors des six variables du bloc standard ` +
        `(déclarée parce qu'un routeur du profil en porte un) ; pas de sonde : l'analyse ne lit le client PPPoE que sur ${WAN1_PORT}.`,
        null, { pattern: WAN1_VLAN_ID_PATTERN },
        [`VLAN relevé sur ${sum.vlan} routeur(s) pppoe.`],
        valued((x) => x.vlanId),
        null,
      );
    }
  }

  /**
   * One row per line of the block: the entries the routers of the block carry
   * for a role are gathered into ONE row (keyed `<menu>#wan1:<role>`), at the
   * place the first of them sat — whatever the alignment paired them with.
   */
  private regroupWan1Rows(): void {
    const plan = this.wan1!;
    const roleOf = new Map<ExportEntry, Wan1Role>();
    for (const shape of plan.shapes) if (shape) for (const [role, e] of shape.roles) roleOf.set(e, role);
    for (const block of this.blocks) {
      const groups = new Map<Wan1Role, { at: number; members: Map<number, ExportEntry> }>();
      const touched = new Set<TemplateRow>();
      block.rows.forEach((row, at) => {
        for (const [s, e] of [...row.members]) {
          const role = roleOf.get(e);
          if (!role) continue;
          let g = groups.get(role);
          if (!g) { g = { at, members: new Map() }; groups.set(role, g); }
          g.members.set(s, e);
          row.members.delete(s);
          touched.add(row);
        }
      });
      if (groups.size === 0) continue;
      const rebuilt: TemplateRow[] = [];
      block.rows.forEach((row, at) => {
        for (const [role, g] of groups) {
          if (g.at !== at) continue;
          const wanRow: TemplateRow = {
            key: `${block.path}#wan1:${role}`,
            path: block.path,
            verb: 'add',
            selectorRaw: null,
            selectorCanon: '',
            positional: [],
            opaqueText: null,
            members: g.members,
            ref: this.refOf(g.members),
            keyOrder: this.keyOrderOf(g.members),
          };
          this.wanRow.set(wanRow, role);
          rebuilt.push(wanRow);
        }
        if (row.members.size === 0) return;
        if (touched.has(row)) {
          row.ref = this.refOf(row.members);
          row.keyOrder = this.keyOrderOf(row.members);
        }
        rebuilt.push(row);
      });
      block.rows = rebuilt;
    }
  }

  /**
   * The lines of a mode no router of the cluster runs, written as the block
   * writes them (the microcode's PPPoE client and its WAN membership; the
   * fixed address). The mode-switch render of the proof checks them.
   */
  private synthesizeWan1Rows(): void {
    const plan = this.wan1!;
    const has = (role: Wan1Role): boolean => [...this.wanRow.values()].includes(role);
    const blockOf = (path: string, before: readonly string[]): PathBlock => {
      let block = this.blocks.find((b) => b.path === path);
      if (block) return block;
      block = { path, ordered: isOrderedSection(path), rows: [] };
      let at = this.blocks.findIndex((b) => before.includes(b.path));
      if (at < 0) at = this.blocks.length;
      this.blocks.splice(at, 0, block);
      return block;
    };
    const add = (path: string, role: Wan1Role, line: string, before: readonly string[], place: (rows: TemplateRow[]) => number): void => {
      const ref = parseRouterOsExport(`${menuHeader(path)}\n${line}\n`).entries[0];
      const row: TemplateRow = {
        key: `${path}#wan1:${role}`, path, verb: 'add', selectorRaw: null, selectorCanon: '', positional: [],
        opaqueText: null, members: new Map(), ref, keyOrder: ref.props.map((p) => p.key),
      };
      const block = blockOf(path, before);
      block.rows.splice(place(block.rows), 0, row);
      this.wanRow.set(row, role);
    };
    const ipFirst = this.blocks.filter((b) => b.path.startsWith('/ip/')).map((b) => b.path);
    if (!has('pppoe')) {
      add('/interface/pppoe-client', 'pppoe',
        `add add-default-route=yes disabled=no interface=${WAN1_PORT} name=ADSL user=stand-in`,
        ['/interface/list/member', ...ipFirst], (rows) => rows.length);
    }
    if (!has('member')) {
      add('/interface/list/member', 'member', `add interface=ADSL list=${WAN_LIST_NAME}`, ipFirst, (rows) => {
        let at = rows.length;
        rows.forEach((r, i) => { if ((propValue(r.ref, 'list') ?? '').toUpperCase() === WAN_LIST_NAME) at = i + 1; });
        return at;
      });
    }
    if (!has('static') && plan.shapes.some((x) => x !== null)) {
      add('/ip/address', 'static', `add address=192.0.2.10/29 interface=${WAN1_PORT}`,
        ipFirst.filter((p) => p !== '/ip/address'), (rows) => rows.length);
    }
  }

  /** Excluded routers: their WAN1 lines were kept out of the alignment; each
   *  is reported with the reason, never templated. */
  private reportExcludedWan1(): void {
    const plan = this.wan1!;
    for (const x of plan.summary!.excluded) {
      const detail =
        `Routeur exclu du bloc WAN1 standard : ${x.reason}. Ni ligne ni valeur wan1_* n'en est tirée ; sans valeur ` +
        'de site, ce modèle le rendrait en dhcp (défaut) — la preuve WAN1 dit ce qui en changerait. Corriger le ' +
        'routeur, ou poser ses valeurs wan1_* à la main, avant de lui affecter le modèle.';
      const lines = plan.pulled.get(x.site) ?? [];
      if (lines.length === 0) this.deviate(x.site, 'missing_line', 'wan1#exclu', 'WAN1', detail);
      for (const e of lines) this.deviate(x.site, 'extra_line', 'wan1#exclu', displayLine(e), detail);
    }
  }

  /** The slots of a line of the block: what the block fixes, then the rest
   *  inferred on the routers of the block like any other line. */
  private planWanSlots(plan: RowPlan): void {
    const row = plan.row;
    const fixed = this.wanFixedSlots(plan);
    for (const k of fixed.keys()) if (!row.keyOrder.includes(k)) row.keyOrder.push(k);
    for (const key of row.keyOrder) {
      const f = fixed.get(key);
      if (f) { plan.slots.set(key, f); continue; }
      if (row.members.size === 0) {
        const raw = propRaw(row.ref, key);
        plan.slots.set(key, raw === undefined ? { kind: 'omit' } : { kind: 'constant', raw });
        continue;
      }
      plan.slots.set(key, this.planSlot(plan, key));
    }
  }

  private wanFixedSlots(plan: RowPlan): Map<string, SlotPlan> {
    const row = plan.row;
    const K = WAN1_KEYS;
    const out = new Map<string, SlotPlan>();
    const use = (name: string, key: string): string => {
      this.wanVars.get(name)!.uses.push(this.useOf(row, key));
      return `{{ ${name} }}`;
    };
    switch (plan.wan) {
      case 'pppoe':
        out.set('interface', this.wan1!.vlan
          ? { kind: 'expr', text: `{% if ${K.vlanId} is defined %}vlan${use(K.vlanId, 'interface')}{% else %}${WAN1_PORT}{% endif %}` }
          : { kind: 'constant', raw: WAN1_PORT });
        out.set('name', { kind: 'expr', text: use(K.pppoeName, 'name') });
        out.set('user', { kind: 'expr', text: use(K.pppoeUsername, 'user') });
        break;
      case 'member':
        out.set('interface', { kind: 'expr', text: use(K.pppoeName, 'interface') });
        break;
      case 'vlan':
        out.set('interface', { kind: 'constant', raw: WAN1_PORT });
        out.set('name', { kind: 'expr', text: `vlan${use(K.vlanId, 'name')}` });
        out.set('vlan-id', { kind: 'expr', text: use(K.vlanId, 'vlan-id') });
        break;
      case 'static':
        out.set('address', { kind: 'expr', text: use(K.address, 'address') });
        if (row.keyOrder.includes('network')) {
          use(K.address, 'network');
          out.set('network', { kind: 'expr', text: `{{ ${K.address} | network }}` });
        }
        out.set('interface', { kind: 'constant', raw: WAN1_PORT });
        break;
      case 'routeNW':
      case 'routeGW':
      case 'netwatch':
        out.set('disabled', {
          kind: 'split', cases: [{ cond: `${K.mode} == "pppoe"`, text: 'yes' }], rest: this.restSlot(plan, 'disabled', 'pppoe'),
        });
        if (plan.wan !== 'netwatch') {
          out.set('gateway', {
            kind: 'split', cases: [{ cond: `${K.mode} == "static"`, text: use(K.gateway, 'gateway') }],
            rest: this.restSlot(plan, 'gateway', 'static'),
          });
        }
        break;
      default:
        break;
    }
    return out;
  }

  /** A slot inferred on the routers of the block that do NOT run `mode`
   *  (the value the other modes keep). */
  private restSlot(plan: RowPlan, key: string, mode: Wan1Mode): SlotPlan {
    const keep = new Map([...plan.row.members].filter(([s]) => this.wan1!.shapes[s]?.mode !== mode));
    if (keep.size === 0) return key === 'disabled' ? { kind: 'constant', raw: 'no' } : { kind: 'omit' };
    const sub: RowPlan = { ...plan, row: { ...plan.row, members: keep, ref: this.refOf(keep) } };
    return this.planSlot(sub, key);
  }

  /** The proposal's WAN1 summary line (French), null for a pure-DHCP cluster. */
  private wan1Warning(): string | null {
    const sum = this.wan1?.summary;
    if (!sum) return null;
    const names = Object.entries(sum.pppoeNames).sort((a, b) => b[1] - a[1]).map(([k, c]) => `${k} ×${c}`).join(', ');
    const counts = `${sum.counts.dhcp} dhcp, ${sum.counts.pppoe} pppoe` +
      `${names ? ` (${names}${sum.vlan > 0 ? `, dont ${sum.vlan} sur VLAN` : ''})` : ''}, ${sum.counts.static} static`;
    const byMode = (['pppoe', 'static', 'dhcp'] as const)
      .map((m) => [m, sum.excluded.filter((x) => x.mode === m).length] as const)
      .filter(([, c]) => c > 0).map(([m, c]) => `${c} ${m}`);
    const unread = sum.excluded.filter((x) => x.mode === null).length;
    if (unread > 0) byMode.push(`${unread} illisible(s)`);
    const excluded = sum.excluded.length === 0
      ? 'aucun routeur exclu'
      : `${sum.excluded.length} routeur(s) exclu(s) du bloc (${byMode.join(', ')}), sans valeur wan1_* : ` +
        `${sum.excluded.slice(0, 8).map((x) => `${this.siteLabel(x.site)} (${x.mode ? `${x.mode} : ` : ''}${x.reason})`).join(' ; ')}` +
        `${sum.excluded.length > 8 ? ` (+${sum.excluded.length - 8})` : ''}`;
    return sum.emitted
      ? `WAN1 : bloc standard émis (wan1_mode par site) — ${counts} ; ${excluded}.`
      : `WAN1 : bloc standard NON émis (${sum.notEmittedReason}) — ${counts} ; ${excluded}. ` +
        'Les lignes WAN1 sont traitées comme les autres lignes (variantes, écarts), et la preuve WAN1 vérifie ' +
        'routeur par routeur qu\'elles sont reproduites à l\'identique.';
  }
}

/** The condition a line of the WAN1 block renders under (null = always). */
function wan1RowCondition(role: Wan1Role, vlan: boolean): string | null {
  const mode = WAN1_KEYS.mode;
  switch (role) {
    case 'pppoe':
    case 'member': return `${mode} == "pppoe"`;
    case 'vlan': return vlan ? `${mode} == "pppoe" and ${WAN1_KEYS.vlanId} is defined` : `${mode} == "pppoe"`;
    case 'static': return `${mode} == "static"`;
    case 'dhcp': return `${mode} != "static"`;
    default: return null;
  }
}

// ============================================================================
// Body helpers
// ============================================================================

/**
 * Literal text of the body. Nunjucks would read `{#` as a comment, and the
 * engine refuses any output still holding `{{ }} {% %}` (findTemplateResidue),
 * so those four are written with a space — RouterOS reads `} }` as `}}` in a
 * script block, and the line is reported (`untemplatable`) for a human to
 * check.
 */
function literal(text: string): string {
  return text
    .replace(/\{\{/g, '{ {').replace(/\}\}/g, '} }')
    .replace(/\{%/g, '{ %').replace(/%\}/g, '% }')
    .replace(/\{#/g, '{% raw %}{#{% endraw %}');
}

/** An address of the LAN, possibly inside literal text. When that text needs
 *  RouterOS quoting (`comment="GW 10.0.0.1"`), the whole value is quoted and
 *  the text escaped the RouterOS way; the filters' output is bare-safe. */
function lanExpr(parts: readonly LanPart[]): string {
  const lits = parts.filter((p) => p.kind === 'lit').map((p) => (p as { text: string }).text).join('');
  const quoted = lits !== '' && encodeRosValue(lits) !== lits;
  const body = parts.map((p) => {
    switch (p.kind) {
      case 'lan': return '{{ lan_subnet }}';
      case 'network': return '{{ lan_subnet | network }}';
      case 'host': return `{{ lan_subnet | cidrHost(${p.index}) }}`;
      case 'prefix': return '{{ lan_subnet | prefixLen }}';
      case 'lit': return literal(quoted ? rosQuoteBody(p.text) : p.text);
    }
  }).join('');
  return quoted ? `"${body}"` : body;
}

function codeExpr(pattern: TextPattern): string {
  const lits = pattern.segments.filter((s) => s.kind === 'lit').map((s) => (s as { text: string }).text).join('');
  const quoted = lits !== '' && encodeRosValue(lits) !== lits;
  const body = pattern.segments.map((s) => {
    if (s.kind === 'ph') {
      if (s.name === 'lan') return '{{ lan_subnet }}';
      if (s.name === 'lan.network') return '{{ lan_subnet | network }}';
      return '{{ site_code }}';
    }
    return literal(quoted ? rosQuoteBody(s.text) : s.text);
  }).join('');
  return quoted ? `"${body}"` : body;
}

function withOverride(override: VarSpec | null, expr: string): string {
  if (!override) return expr;
  return `{% if ${override.name} is defined %}{{ ${override.name} }}{% else %}${expr}{% endif %}`;
}

/** Builds one cluster's proposal (without its reproduction proof). */
export function buildClusterDraft(input: ClusterInput): ClusterDraft {
  return new Extrapolator(input).build();
}

export { evaluateLanParts };
