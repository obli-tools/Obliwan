// ============================================================================
// Fleet take-over — the stopping rule, as a pure function
// ============================================================================
//
// Moved verbatim out of `miner.service.ts` (where it was the body of `mine()`)
// so that the extrapolator's proof harness clusters a synthetic fleet with the
// SAME rule the miner applies to a real one, without a database. The miner
// calls it; nothing about the rule changed in the move. See the box "THE
// STOPPING RULE" at the top of miner.service.ts for why it is the smallest k
// that clears the purity gate and not an elbow or a taste.

import type { BaselineParams, BaselineSlotStat } from '@obliwan/shared/dist/baseline';
import type { DeviceFacts } from './facts';
import {
  alignMembers, bodySlots, cohesionOf, evaluateMember, medoidOf,
  type MemberEvaluation,
} from './align';
import type { ClusterResult } from './cluster';

export interface CandidateCluster {
  members: number[];              // indices into `facts`
  stats: BaselineSlotStat[];
  body: BaselineSlotStat[];
  evaluations: MemberEvaluation[];
  coverageMin: number;
  coverageMean: number;
  cohesion: number;
  medoid: number;
}

export function buildCandidate(
  facts: readonly DeviceFacts[],
  similarity: number[][],
  members: number[],
  params: BaselineParams,
): CandidateCluster {
  const memberFacts = members.map((i) => facts[i]);
  const stats = alignMembers(memberFacts, params);
  const body = bodySlots(stats, params);
  const evaluations = memberFacts.map((m) => evaluateMember(m, body));
  const coverages = evaluations.map((e) => e.coverage);
  return {
    members,
    stats,
    body,
    evaluations,
    coverageMin: coverages.length ? Math.min(...coverages) : 1,
    coverageMean: coverages.length
      ? coverages.reduce((a, b) => a + b, 0) / coverages.length
      : 1,
    cohesion: cohesionOf(similarity, members),
    medoid: medoidOf(similarity, members),
  };
}

/** Assignment array -> member index lists, ordered by first appearance. */
export function partitionOf(assignment: readonly number[]): number[][] {
  const groups = new Map<number, number[]>();
  for (let i = 0; i < assignment.length; i++) {
    const g = groups.get(assignment[i]);
    if (g) g.push(i); else groups.set(assignment[i], [i]);
  }
  return [...groups.entries()].sort((a, b) => a[0] - b[0]).map(([, v]) => v);
}

export interface PartitionChoice {
  /** The chosen partition (or the last one tried when no k cleared the gate). */
  selected: { k: number; clusters: CandidateCluster[] } | null;
  purityGateMet: boolean;
  /** coverage per k tried, in order — the evidence behind the stopping rule. */
  coverageByK: { k: number; coverageMin: number; coverageMean: number }[];
}

/**
 * The smallest k in 1..maxK whose every member clears `minCoverage`. Runs on
 * the calling thread; it stops at the first k that clears the gate, because
 * every later k is work the rule would discard (see miner.service.ts).
 */
export function selectPartition(
  kept: readonly DeviceFacts[],
  clustering: Pick<ClusterResult, 'assignments' | 'similarity'>,
  params: BaselineParams,
  maxK: number,
): PartitionChoice {
  const coverageByK: PartitionChoice['coverageByK'] = [];
  let chosen: { k: number; clusters: CandidateCluster[] } | null = null;
  let fallback: { k: number; clusters: CandidateCluster[] } | null = null;

  for (let k = 1; k <= maxK; k++) {
    const assignment = clustering.assignments[k];
    if (!assignment) continue;
    const clusters = partitionOf(assignment).map((members) =>
      buildCandidate(kept, clustering.similarity, members, params));
    const coverageMin = Math.min(...clusters.map((c) => c.coverageMin));
    const coverageMean =
      clusters.reduce((a, c) => a + c.coverageMean * c.members.length, 0) / kept.length;
    coverageByK.push({ k, coverageMin, coverageMean });
    fallback = { k, clusters };
    if (coverageMin >= params.minCoverage - 1e-9) {
      chosen = { k, clusters };
      break;
    }
  }
  return { selected: chosen ?? fallback, purityGateMet: chosen !== null, coverageByK };
}

// ============================================================================
// Grouping by router MODEL (BaselineParams.partitionBy = 'model')
// ============================================================================

/** The label of the group whose model nobody recorded. */
export const UNKNOWN_MODEL_LABEL = 'Modèle inconnu';

/**
 * The model key of one router: `devices.model` (the routerboard model code the
 * inventory and the identity watch record) wins, else the export preamble's
 * `# model =` (NCM `device.model`, the same code). Each is TRIMMED before it
 * is tested for emptiness — a padded blank is not a model (`Number(' ')` is 0,
 * and `'   '` is truthy) — and cut at 64 (the column). Null = unknown.
 * `config_snapshots.model` is deliberately NOT a source: it holds the board
 * name when the API complement worked and the code otherwise, so it would
 * split one model into two groups.
 */
export function modelKeyOf(deviceModel: string | null | undefined, exportModel: string | null | undefined): string | null {
  for (const raw of [deviceModel, exportModel]) {
    if (typeof raw !== 'string') continue;
    const v = raw.trim();
    if (v !== '') return v.slice(0, 64);
  }
  return null;
}

export interface ModelGroup<T> {
  /** Case-folded key; null = the unknown-model group. */
  key: string | null;
  /** The first spelling seen, or UNKNOWN_MODEL_LABEL. */
  label: string;
  items: T[];
}

/**
 * Group items by model, case-insensitively ("RB5009UG+S+IN" and
 * "rb5009ug+s+in" are one model), the label being the first spelling seen.
 * Groups come out in the order of their first item, so the caller's order
 * (the miner sorts by device id) decides the numbering and the run is
 * deterministic. The unknown group (null key) is a group like the others.
 */
export function groupByModel<T>(items: readonly T[], keyOf: (item: T) => string | null): ModelGroup<T>[] {
  const groups = new Map<string, ModelGroup<T>>();
  const order: string[] = [];
  for (const item of items) {
    const raw = keyOf(item);
    const folded = raw === null ? null : raw.toLowerCase();
    const mapKey = folded === null ? '\u0000unknown' : `m:${folded}`;
    let g = groups.get(mapKey);
    if (!g) {
      g = { key: folded, label: raw ?? UNKNOWN_MODEL_LABEL, items: [] };
      groups.set(mapKey, g);
      order.push(mapKey);
    }
    g.items.push(item);
  }
  return order.map((k) => groups.get(k)!);
}
