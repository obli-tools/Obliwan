// ============================================================================
// Brick 10 — one cluster: proposal + proof, in one call (pure + the worker)
// ============================================================================

import type { ExtrapolatedSiteResult } from '@obliwan/shared';
import { buildClusterDraft, type ClusterDraft, type ClusterInput } from './extrapolate';
import { proveWan1ModeSwitch, reproduceDraft } from './reproduce';
import { wan1LinesOf } from './wan1';

export interface ClusterProposal {
  draft: ClusterDraft;
  sites: ExtrapolatedSiteResult[];
  reproductionMin: number;
  reproductionMean: number;
  /** Every site at or above `params.minReproduction` — and, when a router of
   *  the cluster runs pppoe or static (block emitted or not), every router's
   *  WAN1 lines reproduced exactly and, when the block is emitted, the
   *  mode-switch render proved. */
  gateMet: boolean;
  /** The WAN1 proof, when a router of the cluster runs pppoe or static
   *  (`draft.wan1` not null); null for a pure-DHCP cluster. */
  wan1Proof: {
    /** Routers whose WAN1 lines the proposal renders exactly as they run. */
    reproduced: number;
    /** Indexes (into `input.sites`) of the routers whose WAN1 lines do not. */
    failing: number[];
    /** The mode-switch render's problems (empty = proved). */
    modeSwitch: string[];
  } | null;
}

function round5(x: number): number {
  return Math.round(Math.min(1, Math.max(0, x)) * 100000) / 100000;
}

export async function extrapolateCluster(input: ClusterInput): Promise<ClusterProposal> {
  const draft = buildClusterDraft(input);
  // The WAN1 proof runs as soon as a router of the cluster runs pppoe or
  // static — the block emitted or not: a PPPoE or fixed-IP store whose uplink
  // the proposal renders as DHCP must shut the gate even when its other
  // lines lift its score over the threshold. A pure-DHCP cluster (summary
  // null) is left exactly as it was.
  const withWan1 = draft.wan1 !== null;
  const emitted = draft.wan1?.emitted === true;
  const proofs = await reproduceDraft(draft, draft.parsed, withWan1 ? { focus: wan1LinesOf } : {});
  const sites: ExtrapolatedSiteResult[] = proofs.map((proof, i) => {
    const s = input.sites[i];
    return {
      deviceId: s.deviceId,
      deviceName: s.deviceName,
      siteId: s.siteId,
      siteCode: s.site?.code ?? null,
      snapshotId: s.snapshotId,
      linesActual: proof.comparison.actual,
      linesRendered: proof.comparison.rendered,
      linesReproduced: proof.comparison.matched,
      score: round5(proof.score),
      notReproduced: proof.comparison.notReproduced,
      wouldAdd: proof.comparison.wouldAdd,
      renderError: proof.renderError,
    };
  });

  // The WAN1 block is proved line for line: a router whose uplink the
  // proposal would render differently is reported by name, with its lines,
  // and keeps the gate shut — never averaged into a score.
  let wan1Proof: ClusterProposal['wan1Proof'] = null;
  if (withWan1) {
    const failing: number[] = [];
    // An excluded router's own WAN1 lines are already listed, with the
    // reason it was left out (`wan1#exclu`): not repeated.
    const listed = new Set(draft.deviations.filter((d) => d.slot === 'wan1#exclu').map((d) => `${d.deviceId}\u0000${d.line}`));
    proofs.forEach((proof, i) => {
      const f = proof.focused!;
      if (proof.renderError === null && f.notReproduced.length === 0 && f.wouldAdd.length === 0) return;
      failing.push(i);
      const s = input.sites[i];
      const at = { deviceId: s.deviceId, siteId: s.siteId, siteCode: s.site?.code ?? null };
      const model = emitted
        ? `le modèle (mode ${String(draft.contexts[i].wan1_mode ?? 'dhcp')})`
        : 'le modèle (bloc WAN1 standard non émis)';
      if (proof.renderError !== null) {
        draft.deviations.push({
          ...at, kind: 'untemplatable', slot: 'wan1#preuve', line: 'WAN1',
          detail: `Preuve WAN1 : le rendu de ce routeur est refusé (${proof.renderError.slice(0, 300)}).`,
        });
      }
      for (const line of f.notReproduced) {
        if (listed.has(`${s.deviceId}\u0000${line}`)) continue;
        draft.deviations.push({
          ...at, kind: 'extra_line', slot: 'wan1#preuve', line,
          detail: `Preuve WAN1 : ligne WAN1 du routeur que ${model} ne reproduit pas — ` +
            'pousser ce modèle changerait son accès internet.',
        });
      }
      for (const line of f.wouldAdd) {
        draft.deviations.push({
          ...at, kind: 'missing_line', slot: 'wan1#preuve', line,
          detail: `Preuve WAN1 : ligne WAN1 que ${model} écrirait et que le routeur ne porte pas.`,
        });
      }
    });
    const modeSwitch = await proveWan1ModeSwitch(draft, (i) => input.sites[i].site?.code ?? input.sites[i].deviceName);
    wan1Proof = { reproduced: proofs.length - failing.length, failing, modeSwitch };
    if (failing.length > 0) {
      const names = failing.slice(0, 10).map((i) => input.sites[i].site?.code ?? input.sites[i].deviceName).join(', ');
      draft.warnings.push(
        `Preuve WAN1 : ${failing.length} routeur(s) dont les lignes WAN1 ne sont pas reproduites à l'identique ` +
        `(${names}${failing.length > 10 ? `, +${failing.length - 10}` : ''}) — voir leurs écarts « wan1#preuve » ; ` +
        'ne pas leur affecter ce modèle en l\'état.',
      );
    }
    if (modeSwitch.length > 0) {
      draft.warnings.push(`Preuve WAN1 (changement de mode) en échec : ${modeSwitch.slice(0, 6).join(' ; ')}.`);
    }
    draft.deviations.sort((a, b) => a.deviceId - b.deviceId || a.slot.localeCompare(b.slot));
  }

  const scores = sites.map((s) => s.score);
  const reproductionMin = scores.length ? Math.min(...scores) : 0;
  const reproductionMean = scores.length ? scores.reduce((a, b) => a + b, 0) / scores.length : 0;
  const wan1Ok = wan1Proof === null || (wan1Proof.failing.length === 0 && wan1Proof.modeSwitch.length === 0);
  return {
    draft,
    sites,
    reproductionMin: round5(reproductionMin),
    reproductionMean: round5(reproductionMean),
    gateMet: sites.length > 0 && reproductionMin >= input.params.minReproduction - 1e-9 && wan1Ok,
    wan1Proof,
  };
}

export { buildClusterDraft, reproduceDraft };
export type { ClusterDraft, ClusterInput };
export type { ExistingProbe, ExistingValue, ExtrapolationSiteInput } from './extrapolate';
