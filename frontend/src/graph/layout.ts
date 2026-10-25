/**
 * Deterministic layout: nodes are seeded into left-to-right x-bands by type
 * (internet and ingress left, services and controls in the middle, IAM roles
 * then data stores right), then fcose refines without randomising.
 */

import type { Core, LayoutOptions, NodeSingular, Position } from 'cytoscape';

import type { GraphNode } from '../api/types';
import { asKind, RANK } from './glyphs';

const BAND_WIDTH = 230;
const ROW_HEIGHT = 58;

/** A stable hash so the same graph lays out the same way on every load. */
function digest(value: string): number {
  let hash = 0;
  for (let index = 0; index < value.length; index += 1) {
    hash = (hash * 31 + value.charCodeAt(index)) % 100000;
  }
  return hash;
}

export function seedPositions(nodes: GraphNode[]): Record<string, Position> {
  const byRank = new Map<number, GraphNode[]>();
  for (const node of nodes) {
    const rank = RANK[asKind(node.label)];
    const bucket = byRank.get(rank) ?? [];
    bucket.push(node);
    byRank.set(rank, bucket);
  }
  const positions: Record<string, Position> = {};
  for (const [rank, bucket] of [...byRank.entries()].sort((a, b) => a[0] - b[0])) {
    const ordered = [...bucket].sort((a, b) => a.id.localeCompare(b.id));
    const offset = ((ordered.length - 1) * ROW_HEIGHT) / 2;
    ordered.forEach((node, index) => {
      positions[node.id] = {
        x: rank * BAND_WIDTH + (digest(node.id) % 44) - 22,
        y: index * ROW_HEIGHT - offset + (digest(`${node.id}y`) % 18) - 9,
      };
    });
  }
  return positions;
}

/** One representative per rank keeps the left-to-right ordering under fcose. */
function rankRepresentatives(nodes: GraphNode[]): { rank: number; id: string }[] {
  const seen = new Map<number, string>();
  for (const node of [...nodes].sort((a, b) => a.id.localeCompare(b.id))) {
    const rank = RANK[asKind(node.label)];
    if (!seen.has(rank)) seen.set(rank, node.id);
  }
  return [...seen.entries()]
    .map(([rank, id]) => ({ rank, id }))
    .sort((a, b) => a.rank - b.rank);
}

export function layoutOptions(nodes: GraphNode[]): LayoutOptions {
  const reps = rankRepresentatives(nodes);
  const relative: { left: string; right: string; gap: number }[] = [];
  for (let index = 0; index < reps.length - 1; index += 1) {
    const left = reps[index];
    const right = reps[index + 1];
    if (left && right) relative.push({ left: left.id, right: right.id, gap: BAND_WIDTH });
  }
  const internet = nodes.find((node) => node.label === 'Internet');
  return {
    name: 'fcose',
    quality: 'proof',
    randomize: false,
    animate: false,
    fit: true,
    padding: 28,
    nodeSeparation: 90,
    nodeRepulsion: () => 7000,
    idealEdgeLength: (edge: { data: (key: string) => unknown }) =>
      edge.data('type') === 'CALLS' ? 130 : 95,
    edgeElasticity: () => 0.3,
    gravity: 0.18,
    gravityRangeCompound: 1.2,
    numIter: 2500,
    tile: false,
    packComponents: true,
    uniformNodeDimensions: false,
    relativePlacementConstraint: relative.length > 0 ? relative : undefined,
    fixedNodeConstraint: internet
      ? [{ nodeId: internet.id, position: { x: -BAND_WIDTH, y: 0 } }]
      : undefined,
  } as unknown as LayoutOptions;
}

export function applySeed(cy: Core, nodes: GraphNode[]): void {
  const positions = seedPositions(nodes);
  cy.nodes().forEach((node: NodeSingular) => {
    const position = positions[node.id()];
    if (position) node.position(position);
  });
}
