/** Graph view state: the loaded subgraph, highlights, selection and layers. */

import { create } from 'zustand';

import { api } from '../api/client';
import type { GraphEdge, GraphNode, SubgraphResponse } from '../api/types';

export type Layer = 'estate' | 'paths' | 'controls' | 'memory';

interface GraphState {
  nodes: GraphNode[];
  edges: GraphEdge[];
  truncated: boolean;
  hiddenNodes: number;
  latencyMs: number;
  loading: boolean;
  error: string | null;
  highlighted: string[];
  highlightReason: string;
  selectedNodeId: string | null;
  selectedPathId: string | null;
  pathNodeIds: string[];
  pathEdgeKeys: string[];
  layers: Record<Layer, boolean>;
  loadFocus: (kind?: string) => Promise<void>;
  loadSubgraph: (ids: string[], hops?: number) => Promise<void>;
  expand: (ids: string[]) => Promise<void>;
  highlight: (ids: string[], reason: string) => void;
  clearHighlight: () => void;
  selectNode: (id: string | null) => void;
  selectPath: (pathId: string | null, nodeIds: string[], edgeKeys: string[]) => void;
  toggleLayer: (layer: Layer) => void;
}

function merge(current: SubgraphResponse, incoming: SubgraphResponse): SubgraphResponse {
  const nodes = new Map(current.nodes.map((node) => [node.id, node]));
  for (const node of incoming.nodes) nodes.set(node.id, node);
  const edges = new Map(current.edges.map((edge) => [edge.id, edge]));
  for (const edge of incoming.edges) edges.set(edge.id, edge);
  return {
    nodes: [...nodes.values()],
    edges: [...edges.values()],
    truncated: current.truncated || incoming.truncated,
    hidden_nodes: Math.max(current.hidden_nodes, incoming.hidden_nodes),
    latency_ms: incoming.latency_ms,
  };
}

export const useGraph = create<GraphState>((set, get) => ({
  nodes: [],
  edges: [],
  truncated: false,
  hiddenNodes: 0,
  latencyMs: 0,
  loading: false,
  error: null,
  highlighted: [],
  highlightReason: '',
  selectedNodeId: null,
  selectedPathId: null,
  pathNodeIds: [],
  pathEdgeKeys: [],
  layers: { estate: true, paths: true, controls: true, memory: false },

  loadFocus: async (kind = 'attack_surface') => {
    set({ loading: true, error: null });
    try {
      const data = await api.focus(kind);
      set({
        nodes: data.nodes,
        edges: data.edges,
        truncated: data.truncated,
        hiddenNodes: data.hidden_nodes,
        latencyMs: data.latency_ms,
        loading: false,
      });
    } catch (error) {
      set({ loading: false, error: error instanceof Error ? error.message : 'Graph load failed.' });
    }
  },

  loadSubgraph: async (ids, hops = 1) => {
    if (ids.length === 0) return;
    set({ loading: true, error: null });
    try {
      const data = await api.subgraph(ids, hops);
      set({
        nodes: data.nodes,
        edges: data.edges,
        truncated: data.truncated,
        hiddenNodes: data.hidden_nodes,
        latencyMs: data.latency_ms,
        loading: false,
      });
    } catch (error) {
      set({ loading: false, error: error instanceof Error ? error.message : 'Graph load failed.' });
    }
  },

  expand: async (ids) => {
    const unknown = ids.filter((id) => !get().nodes.some((node) => node.id === id));
    if (unknown.length === 0) return;
    try {
      const incoming = await api.subgraph(unknown.slice(0, 40), 0);
      const state = get();
      const merged = merge(
        {
          nodes: state.nodes,
          edges: state.edges,
          truncated: state.truncated,
          hidden_nodes: state.hiddenNodes,
          latency_ms: state.latencyMs,
        },
        incoming,
      );
      set({
        nodes: merged.nodes,
        edges: merged.edges,
        truncated: merged.truncated,
        hiddenNodes: merged.hidden_nodes,
        latencyMs: merged.latency_ms,
      });
    } catch (error) {
      set({ error: error instanceof Error ? error.message : 'Could not expand the graph.' });
    }
  },

  highlight: (ids, reason) => set({ highlighted: ids, highlightReason: reason }),
  clearHighlight: () =>
    set({
      highlighted: [],
      highlightReason: '',
      selectedPathId: null,
      pathNodeIds: [],
      pathEdgeKeys: [],
    }),
  selectNode: (id) => set({ selectedNodeId: id }),
  selectPath: (pathId, nodeIds, edgeKeys) =>
    set({ selectedPathId: pathId, pathNodeIds: nodeIds, pathEdgeKeys: edgeKeys }),
  toggleLayer: (layer) =>
    set((state) => ({ layers: { ...state.layers, [layer]: !state.layers[layer] } })),
}));
