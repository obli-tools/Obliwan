// ============================================================================
// ObliWAN — the break-risk verdict (learning mode)
// ============================================================================
//
// PURE. "What would this template break on this router in production?" — the
// plan a push would compile (its ops, their risk signals, the uplink guard's
// refusals) and the line-by-line comparison of the template's render with the
// router's own export, judged row by row.
//
// DELIBERATELY NOISY. On a router in learning, the operator would rather read
// a hundred lines than miss one, so the DEFAULT is "flagged":
//  - every plan op is flagged, except a `verify` (it changes nothing);
//  - every production line the template does not reproduce is flagged
//    (`production_only`; `unmodeled` too when the menu is outside the NCM — a
//    push cannot change it, a manual migration will);
//  - every template line production does not carry is flagged
//    (`template_only`), with ONE exception, `inert_addition`: an `add` of an
//    address-list entry or a script whose name no production line mentions —
//    nothing on the box can reach it.
//  - a comment-only update is flagged `comment_selector`, because this fleet's
//    scripts select routes BY COMMENT (`WAN1-GW`, `NW-WAN1`): renaming a
//    comment silently disables a failover.
// Lines matched on both sides are only counted.

import type { BreakRiskDomain, BreakRiskReason, BreakRiskRow, NcmResourceKind, PlanOp } from '@obliwan/shared';
import type { ExportEntry } from '../baseline/extrapolator/exportText';
import { displayLine } from '../baseline/extrapolator/exportText';
import type { DetailedComparison } from '../baseline/extrapolator/reproduce';
import { sectionSpec } from '../drivers/mikrotik/quirks';
import type { RiskAssessment } from './riskScoring';
import { UPLINK_BLOCK_REASON } from './uplinkGuard';

// ============================================================================
// Domains
// ============================================================================

/** Menu path prefix → domain. The LONGEST matching prefix wins. */
const PATH_DOMAINS: ReadonlyArray<readonly [string, BreakRiskDomain]> = [
  ['/interface/pppoe-client', 'uplink'],
  ['/ip/dhcp-client', 'uplink'],
  ['/interface/list', 'uplink'],
  ['/interface/lte', 'lte'],
  ['/interface/wireless', 'wireless'],
  ['/interface/wifi', 'wireless'],
  ['/interface/wifiwave2', 'wireless'],
  ['/caps-man', 'wireless'],
  ['/interface/bridge', 'bridge_vlan'],
  ['/interface/vlan', 'bridge_vlan'],
  ['/interface/l2tp-client', 'ppp'],
  ['/interface/l2tp-server', 'ppp'],
  ['/interface/pptp-client', 'ppp'],
  ['/interface/sstp-client', 'ppp'],
  ['/interface/ovpn-client', 'ppp'],
  ['/ppp', 'ppp'],
  ['/interface/gre', 'ipsec'],
  ['/interface/wireguard', 'ipsec'],
  ['/interface', 'interfaces'],
  ['/ip/address', 'addresses'],
  ['/ipv6/address', 'addresses'],
  ['/ip/route', 'routes'],
  ['/ipv6/route', 'routes'],
  ['/routing', 'routes'],
  ['/ip/firewall/nat', 'nat'],
  ['/ip/firewall/address-list', 'address_lists'],
  ['/ip/firewall', 'firewall'],
  ['/ipv6/firewall', 'firewall'],
  ['/ip/ipsec', 'ipsec'],
  ['/ip/dhcp-server', 'dhcp'],
  ['/ip/pool', 'dhcp'],
  ['/ip/dns', 'dns'],
  ['/ip/service', 'management'],
  ['/ip/ssh', 'management'],
  ['/ip/neighbor', 'management'],
  ['/tool/mac-server', 'management'],
  ['/tool/romon', 'management'],
  ['/certificate', 'management'],
  ['/system/identity', 'management'],
  ['/user', 'users'],
  ['/system/script', 'scripts'],
  ['/system/scheduler', 'scripts'],
  ['/tool/netwatch', 'netwatch'],
  ['/queue', 'qos'],
  ['/snmp', 'snmp'],
  ['/system/clock', 'time'],
  ['/system/ntp', 'time'],
  ['/system/logging', 'logging'],
];

const SORTED_PATH_DOMAINS = [...PATH_DOMAINS].sort((a, b) => b[0].length - a[0].length);

export function domainOfPath(path: string): BreakRiskDomain {
  for (const [prefix, domain] of SORTED_PATH_DOMAINS) {
    if (path === prefix || path.startsWith(`${prefix}/`)) return domain;
  }
  return 'other';
}

/** Every `NcmResourceKind` has a domain — the harness asserts it. */
export const RESOURCE_DOMAINS: Readonly<Record<NcmResourceKind, BreakRiskDomain>> = {
  interface: 'interfaces',
  vlan: 'bridge_vlan',
  route: 'routes',
  firewallRule: 'firewall',
  natRule: 'nat',
  dhcpScope: 'dhcp',
  ipsecPeer: 'ipsec',
  localUser: 'users',
  service: 'management',
  qosRule: 'qos',
  dhcpClient: 'uplink',
};

function isPppoeRecord(v: unknown): boolean {
  return !!v && typeof v === 'object' && (v as { type?: unknown }).type === 'pppoe';
}

export function domainOfOp(op: Pick<PlanOp, 'resource' | 'before' | 'after'>): BreakRiskDomain {
  if (op.resource === 'interface' && (isPppoeRecord(op.before) || isPppoeRecord(op.after))) return 'uplink';
  return RESOURCE_DOMAINS[op.resource] ?? 'other';
}

// ============================================================================
// The verdict
// ============================================================================

export interface BreakRiskInput {
  ops: readonly PlanOp[];
  signals: Readonly<Record<number, RiskAssessment>>;
  /** op seq → the uplink guard's clauses for it (`checkPlanUplinks`). */
  uplinkRefusalsBySeq: ReadonlyMap<number, readonly string[]>;
  comparison: DetailedComparison | null;
  /** Every production entry, for the "is this name mentioned" test. */
  actualEntries: readonly ExportEntry[];
}

function escapeRe(s: string): string {
  return s.replace(/[.*+^${}()|[\]\\]/g, '\\$&').replace(/\?/g, '\\?');
}

/** Is `name` mentioned by any production line, as a whole word? */
function mentioned(name: string, entries: readonly ExportEntry[]): boolean {
  if (name === '') return true;
  const re = new RegExp(`(^|[^A-Za-z0-9_-])${escapeRe(name)}($|[^A-Za-z0-9_-])`);
  for (const e of entries) {
    if (e.verb === 'opaque') {
      if (re.test(e.text)) return true;
      continue;
    }
    for (const p of e.props) if (p.value === name || re.test(p.value)) return true;
    if (re.test(e.selectorCanon)) return true;
  }
  return false;
}

/** An addition nothing on the box can reach. */
function isInertAddition(e: ExportEntry, actual: readonly ExportEntry[]): boolean {
  if (e.verb !== 'add') return false;
  const prop = e.path === '/ip/firewall/address-list' ? 'list' : e.path === '/system/script' ? 'name' : null;
  if (!prop) return false;
  const name = e.props.find((p) => p.key === prop)?.value;
  if (name === undefined || name === '') return false;
  return !mentioned(name, actual);
}

function isModeled(path: string): boolean {
  return !!sectionSpec(path)?.ncmResourceKind;
}

export function assessBreakRisk(input: BreakRiskInput): BreakRiskRow[] {
  const rows: BreakRiskRow[] = [];

  // ── Plan rows ──────────────────────────────────────────────────────────
  for (const op of input.ops) {
    const line = `${op.kind} ${op.resource} ${op.semKey}`;
    const domain = domainOfOp(op);
    const signal = input.signals[op.seq];
    if (op.kind === 'verify') {
      rows.push({
        source: 'plan', verdict: 'harmless', domain, side: null, line, opSeq: op.seq, risk: op.risk,
        reasons: ['verify_only'], detail: op.reason || null,
      });
      continue;
    }
    const reasons: BreakRiskReason[] = ['plan_op'];
    if (op.kind === 'blocked') {
      reasons.push(op.blockedReason === UPLINK_BLOCK_REASON ? 'uplink_preserved' : 'blocked');
    }
    if ((input.uplinkRefusalsBySeq.get(op.seq)?.length ?? 0) > 0 && !reasons.includes('uplink_preserved')) {
      reasons.push('uplink_preserved');
    }
    if (signal?.tunnelCritical) reasons.push('management_path');
    if (op.kind === 'delete') reasons.push('deletion');
    if (
      op.kind === 'update'
      && op.fields.length > 0
      && op.fields.every((f) => f.split('.')[0] === 'comment')
    ) {
      reasons.push('comment_selector');
    }
    const clauses = input.uplinkRefusalsBySeq.get(op.seq) ?? [];
    const detail = [signal?.reason ?? op.reason, ...clauses].filter((s) => !!s).join(' | ').slice(0, 1000) || null;
    rows.push({
      source: 'plan', verdict: 'flagged', domain, side: null, line, opSeq: op.seq, risk: op.risk, reasons, detail,
    });
  }

  // ── Text rows ──────────────────────────────────────────────────────────
  const c = input.comparison;
  if (c) {
    for (const e of c.notReproducedEntries) {
      const reasons: BreakRiskReason[] = ['production_only'];
      if (!isModeled(e.path)) reasons.push('unmodeled');
      rows.push({
        source: 'text', verdict: 'flagged', domain: domainOfPath(e.path), side: 'production_only',
        line: displayLine(e), opSeq: null, risk: null, reasons, detail: null,
      });
    }
    for (const e of c.wouldAddEntries) {
      if (isInertAddition(e, input.actualEntries)) {
        rows.push({
          source: 'text', verdict: 'harmless', domain: domainOfPath(e.path), side: 'template_only',
          line: displayLine(e), opSeq: null, risk: null, reasons: ['template_only', 'inert_addition'], detail: null,
        });
        continue;
      }
      const reasons: BreakRiskReason[] = ['template_only'];
      if (!isModeled(e.path)) reasons.push('unmodeled');
      rows.push({
        source: 'text', verdict: 'flagged', domain: domainOfPath(e.path), side: 'template_only',
        line: displayLine(e), opSeq: null, risk: null, reasons, detail: null,
      });
    }
  }
  return rows;
}
