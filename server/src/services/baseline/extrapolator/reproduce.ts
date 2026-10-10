// ============================================================================
// Brick 10 — the reproduction proof
// ============================================================================
//
// A proposal is not judged on how plausible it looks. Each site's proposal is
// RENDERED — by the template worker every published revision goes through
// (`renderTemplates`: vm realm, resource limits, 5 s, RouterOS escaping on every
// `{{ }}`, residue refusal), with the site's inferred values and every secret as
// its placeholder — and the output is DIFFED against the redacted export the
// router actually produced.
//
// The comparison is what RouterOS would read, not how it was spelled: property
// order is ignored, a value quoted on one side and bare on the other is the
// same value, a secret is absent on both sides (the export never carries one).
// In an ordered menu (firewall, NAT, queues… and every menu the catalogue does
// not know) the lines must also come in the same order — the longest common
// subsequence is what counts; elsewhere a line is matched wherever it is.
//
//   score = reproduced / (device lines + template lines - reproduced)
//
// so a line the template misses and a line it would add both cost. The exact
// lines on either side are returned, capped, so an operator reads WHAT is not
// reproduced rather than a percentage.

import { renderTemplates } from '../../template/engine';
import {
  canonicalKey, displayLine, isOrderedSection, parseRouterOsExport,
  type ExportEntry, type ParsedRouterOsExport,
} from './exportText';
import type { ClusterDraft } from './extrapolate';
import { WAN1_KEYS, wan1LinesOf, wan1StandInProblems, wan1StandIns } from './wan1';

export const REPRODUCTION_LINE_CAP = 200;

export interface Comparison {
  actual: number;
  rendered: number;
  matched: number;
  notReproduced: string[];
  wouldAdd: string[];
}

function groupOf(e: ExportEntry): string {
  return e.verb === 'opaque' ? '::opaque' : e.path;
}

function lcsMatches(a: readonly string[], b: readonly string[]): { aHit: boolean[]; bHit: boolean[] } {
  const n = a.length;
  const m = b.length;
  const dp: Uint32Array[] = Array.from({ length: n + 1 }, () => new Uint32Array(m + 1));
  for (let i = n - 1; i >= 0; i--) {
    for (let j = m - 1; j >= 0; j--) {
      dp[i][j] = a[i] === b[j] ? dp[i + 1][j + 1] + 1 : Math.max(dp[i + 1][j], dp[i][j + 1]);
    }
  }
  const aHit = new Array<boolean>(n).fill(false);
  const bHit = new Array<boolean>(m).fill(false);
  let i = 0;
  let j = 0;
  while (i < n && j < m) {
    if (a[i] === b[j]) { aHit[i] = true; bHit[j] = true; i++; j++; }
    else if (dp[i + 1][j] >= dp[i][j + 1]) i++;
    else j++;
  }
  return { aHit, bHit };
}

/** `compareEntries` plus the ENTRIES on either side (capped at `cap`), for a
 *  caller that judges each line (the learning break-risk report). */
export interface DetailedComparison extends Comparison {
  notReproducedEntries: ExportEntry[];
  wouldAddEntries: ExportEntry[];
}

/** Device entries against rendered entries, menu by menu. */
export function compareEntries(actual: readonly ExportEntry[], rendered: readonly ExportEntry[]): Comparison {
  const d = compareEntriesDetailed(actual, rendered, REPRODUCTION_LINE_CAP);
  return { actual: d.actual, rendered: d.rendered, matched: d.matched, notReproduced: d.notReproduced, wouldAdd: d.wouldAdd };
}

/** The comparison of `compareEntries`, with the unmatched entries themselves. */
export function compareEntriesDetailed(
  actual: readonly ExportEntry[],
  rendered: readonly ExportEntry[],
  cap: number = REPRODUCTION_LINE_CAP,
): DetailedComparison {
  const groups = new Map<string, { a: ExportEntry[]; r: ExportEntry[] }>();
  const order: string[] = [];
  const add = (e: ExportEntry, side: 'a' | 'r'): void => {
    const g = groupOf(e);
    let entry = groups.get(g);
    if (!entry) { entry = { a: [], r: [] }; groups.set(g, entry); order.push(g); }
    entry[side].push(e);
  };
  for (const e of actual) add(e, 'a');
  for (const e of rendered) add(e, 'r');

  let matched = 0;
  const notReproduced: string[] = [];
  const wouldAdd: string[] = [];
  const notReproducedEntries: ExportEntry[] = [];
  const wouldAddEntries: ExportEntry[] = [];
  for (const g of order) {
    const { a, r } = groups.get(g)!;
    const ka = a.map(canonicalKey);
    const kr = r.map(canonicalKey);
    let aHit: boolean[];
    let rHit: boolean[];
    if (g === '::opaque' || isOrderedSection(g)) {
      ({ aHit, bHit: rHit } = lcsMatches(ka, kr));
    } else {
      aHit = new Array<boolean>(ka.length).fill(false);
      rHit = new Array<boolean>(kr.length).fill(false);
      const pool = new Map<string, number[]>();
      kr.forEach((k, j) => { const list = pool.get(k); if (list) list.push(j); else pool.set(k, [j]); });
      ka.forEach((k, i) => {
        const list = pool.get(k);
        if (list && list.length > 0) { aHit[i] = true; rHit[list.shift()!] = true; }
      });
    }
    aHit.forEach((hit, i) => {
      if (hit) matched++;
      else if (notReproduced.length < cap) {
        notReproduced.push(displayLine(a[i]));
        notReproducedEntries.push(a[i]);
      }
    });
    rHit.forEach((hit, j) => {
      if (!hit && wouldAdd.length < cap) {
        wouldAdd.push(displayLine(r[j]));
        wouldAddEntries.push(r[j]);
      }
    });
  }
  return {
    actual: actual.length, rendered: rendered.length, matched, notReproduced, wouldAdd,
    notReproducedEntries, wouldAddEntries,
  };
}

export function scoreOf(c: Comparison): number {
  const denominator = c.actual + c.rendered - c.matched;
  return denominator === 0 ? 1 : c.matched / denominator;
}

export interface SiteReproduction {
  comparison: Comparison;
  score: number;
  renderError: string | null;
  /** With `focus`: the same comparison, restricted on BOTH sides to the lines
   *  `focus` selects (the WAN1 lines, for the WAN1 block's own proof). */
  focused?: Comparison;
}

export interface ReproduceOptions {
  /** Selects, from an export, the lines a second comparison is limited to. */
  focus?: (entries: readonly ExportEntry[]) => ExportEntry[];
}

/**
 * Renders the draft for every site and compares. Never throws for a site's
 * sake: a site whose render is refused scores 0 and says why.
 */
export async function reproduceDraft(
  draft: ClusterDraft,
  parsedActual: readonly ParsedRouterOsExport[] = draft.parsed,
  options: ReproduceOptions = {},
): Promise<SiteReproduction[]> {
  const requests = draft.contexts.map((context, i) => ({
    id: `site-${i}`,
    entry: 'proposal',
    sources: { proposal: draft.body },
    context,
  }));
  const results = await renderTemplates(requests);
  const focus = options.focus;
  return results.map((res, i) => {
    const actual = parsedActual[i].entries;
    if (!res.ok || res.output === null) {
      const refused = (lines: readonly ExportEntry[]): Comparison => ({
        actual: lines.length,
        rendered: 0,
        matched: 0,
        notReproduced: lines.slice(0, REPRODUCTION_LINE_CAP).map(displayLine),
        wouldAdd: [],
      });
      return {
        comparison: refused(actual),
        score: 0,
        renderError: `${res.errorKind ?? 'error'}: ${(res.errorMessage ?? 'render failed').slice(0, 1000)}`,
        ...(focus ? { focused: refused(focus(actual)) } : {}),
      };
    }
    const rendered = parseRouterOsExport(res.output).entries;
    const comparison = compareEntries(actual, rendered);
    return {
      comparison,
      score: scoreOf(comparison),
      renderError: null,
      ...(focus ? { focused: compareEntries(focus(actual), focus(rendered)) } : {}),
    };
  });
}

/**
 * The WAN1 block's MODE-SWITCH proof. The per-router proof shows each mode on
 * the routers that run it; a mode no router of the cluster runs (the fixed
 * address of a fleet with no fixed-IP store, the PPPoE client of a fleet with
 * none) is written from the standard block and proved here instead: the
 * routers of the block are rendered in every mode with documentation-range
 * stand-ins, and each render must itself carry the standard block in that
 * mode with exactly those values (`assessWan1Site`), and its lines outside
 * WAN1 must be the same in every mode — switching a store's uplink changes
 * its uplink and nothing else. One router per distinct WAN1 shape
 * (`summary.baseSites`): a router whose own lines of the block differ (a DHCP
 * client that sets its own default route, say) is proved on its own, so the
 * verdict never depends on which router comes first. Empty = proved;
 * otherwise French reasons, each naming the router (`labelOf`).
 */
export async function proveWan1ModeSwitch(
  draft: ClusterDraft,
  labelOf: (site: number) => string = (site) => `routeur #${site + 1}`,
): Promise<string[]> {
  const summary = draft.wan1;
  if (!summary?.emitted || summary.baseSites.length === 0) return [];
  const standIns = wan1StandIns(draft.variables.some((v) => v.name === WAN1_KEYS.vlanId));
  const keys = Object.values(WAN1_KEYS).filter((k) => k !== WAN1_KEYS.pppoePassword);
  const jobs = summary.baseSites.flatMap((site) => standIns.map((standIn, i) => ({ site, standIn, i })));
  const results = await renderTemplates(jobs.map(({ site, standIn, i }) => {
    const context: Record<string, unknown> = { ...draft.contexts[site] };
    for (const k of keys) delete context[k];
    Object.assign(context, standIn.values);
    // The schema default the resolver would apply.
    if (context[WAN1_KEYS.pppoeName] === undefined) context[WAN1_KEYS.pppoeName] = 'ADSL';
    return { id: `wan1-${site}-${i}`, entry: 'proposal', sources: { proposal: draft.body }, context };
  }));
  const problems: string[] = [];
  const reference = new Map<number, string>();
  results.forEach((res, j) => {
    const { site, standIn } = jobs[j];
    const label = `${labelOf(site)}, ${standIn.label}`;
    if (!res.ok || res.output === null) {
      problems.push(`${label} : rendu refusé (${(res.errorMessage ?? 'erreur').slice(0, 300)})`);
      return;
    }
    const entries = parseRouterOsExport(res.output).entries;
    for (const p of wan1StandInProblems(standIn, entries)) problems.push(`${label} : ${p}`);
    const wan = new Set(wan1LinesOf(entries));
    const rest = entries.filter((e) => !wan.has(e)).map(canonicalKey).sort().join('\n');
    const ref = reference.get(site);
    if (ref === undefined) reference.set(site, rest);
    else if (rest !== ref) problems.push(`${label} : le changement de mode modifie aussi des lignes hors WAN1`);
  });
  return problems;
}
