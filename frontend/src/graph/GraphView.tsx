/**
 * The map. Cytoscape with the paper stylesheet, deterministic fcose layout,
 * neighbour emphasis on hover, path emphasis on selection and a slow dash
 * march on attack-path edges (off under prefers-reduced-motion).
 */

import cytoscape, { type Core, type EdgeSingular, type NodeSingular } from 'cytoscape';
import fcose from 'cytoscape-fcose';
import { useEffect, useRef, type ReactNode } from 'react';

import type { GraphEdge, GraphNode } from '../api/types';
import { EmptyState } from '../components/EmptyState';
import { ErrorBlock } from '../components/ErrorBlock';
import { Loading } from '../components/Loading';
import { buildStylesheet, toElements } from './cyStyle';
import { applySeed, layoutOptions } from './layout';

let registered = false;
function register(): void {
  if (registered) return;
  try {
    cytoscape.use(fcose);
  } catch {
    // Re-registering the same extension is harmless; the layout stays available.
  }
  registered = true;
}

const LABEL_ZOOM = 0.8;
const MARCH_INTERVAL_MS = 100;
const MARCH_STEP_PX = 0.5;
const DASH_PERIOD_PX = 10;

export interface GraphViewProps {
  nodes: GraphNode[];
  edges: GraphEdge[];
  highlighted?: string[];
  pathNodeIds?: string[];
  pathEdgeKeys?: string[];
  mitigatedEdgeKeys?: string[];
  selectedNodeId?: string | null;
  onSelectNode?: (id: string | null) => void;
  loading?: boolean;
  error?: string | null;
  onRetry?: () => void;
  emptyAction?: ReactNode;
}

function prefersReducedMotion(): boolean {
  return window.matchMedia('(prefers-reduced-motion: reduce)').matches;
}

export function GraphView({
  nodes,
  edges,
  highlighted = [],
  pathNodeIds = [],
  pathEdgeKeys = [],
  mitigatedEdgeKeys = [],
  selectedNodeId = null,
  onSelectNode,
  loading = false,
  error = null,
  onRetry,
  emptyAction,
}: GraphViewProps) {
  const hostRef = useRef<HTMLDivElement | null>(null);
  const cyRef = useRef<Core | null>(null);
  const selectRef = useRef(onSelectNode);
  selectRef.current = onSelectNode;

  useEffect(() => {
    register();
    const host = hostRef.current;
    if (!host) return undefined;
    const cy = cytoscape({
      container: host,
      style: buildStylesheet(),
      elements: [],
      minZoom: 0.15,
      maxZoom: 3,
      wheelSensitivity: 0.2,
      boxSelectionEnabled: false,
      textureOnViewport: false,
    });
    cyRef.current = cy;

    const syncLabels = () => {
      if (cy.zoom() >= LABEL_ZOOM) cy.nodes().addClass('labelled');
      else cy.nodes().removeClass('labelled');
    };
    cy.on('zoom', syncLabels);
    cy.on('mouseover', 'node', (event) => {
      const node = event.target as NodeSingular;
      node.addClass('labelled');
      node.neighborhood().addClass('neighbour');
      node.neighborhood('node').addClass('labelled');
    });
    cy.on('mouseout', 'node', (event) => {
      const node = event.target as NodeSingular;
      cy.elements().removeClass('neighbour');
      if (cy.zoom() < LABEL_ZOOM) {
        node.removeClass('labelled');
        node.neighborhood('node').removeClass('labelled');
      }
    });
    cy.on('tap', 'node', (event) => {
      const node = event.target as NodeSingular;
      selectRef.current?.(node.id());
    });
    cy.on('tap', (event) => {
      if (event.target === cy) selectRef.current?.(null);
    });

    return () => {
      cy.destroy();
      cyRef.current = null;
    };
  }, []);

  useEffect(() => {
    const cy = cyRef.current;
    if (!cy) return;
    const elements = toElements(nodes, edges);
    cy.batch(() => {
      cy.elements().remove();
      cy.add(elements);
    });
    if (nodes.length === 0) return;
    applySeed(cy, nodes);
    try {
      cy.layout(layoutOptions(nodes)).run();
    } catch {
      cy.layout({ name: 'cose', animate: false }).run();
    }
    cy.fit(undefined, 30);
    if (cy.zoom() >= LABEL_ZOOM) cy.nodes().addClass('labelled');
  }, [nodes, edges]);

  useEffect(() => {
    const cy = cyRef.current;
    if (!cy) return;
    cy.batch(() => {
      cy.nodes().removeClass('highlighted');
      for (const id of highlighted) cy.getElementById(id).addClass('highlighted');
    });
  }, [highlighted]);

  useEffect(() => {
    const cy = cyRef.current;
    if (!cy) return;
    const pathSet = new Set(pathNodeIds);
    cy.batch(() => {
      cy.elements().removeClass('on-path dimmed mitigated');
      for (const key of mitigatedEdgeKeys) cy.getElementById(key).addClass('mitigated');
      if (pathSet.size === 0) return;
      for (const id of pathSet) cy.getElementById(id).addClass('on-path');
      for (const key of pathEdgeKeys) cy.getElementById(key).addClass('on-path');
      cy.nodes().forEach((node: NodeSingular) => {
        if (!pathSet.has(node.id())) node.addClass('dimmed');
      });
      cy.edges().forEach((edge: EdgeSingular) => {
        if (!edge.hasClass('on-path')) edge.addClass('dimmed');
      });
    });
  }, [pathNodeIds, pathEdgeKeys, mitigatedEdgeKeys]);

  useEffect(() => {
    const cy = cyRef.current;
    if (!cy) return;
    cy.nodes().unselect();
    if (selectedNodeId) {
      const node = cy.getElementById(selectedNodeId);
      if (node.nonempty()) {
        node.select();
        cy.animate({ center: { eles: node } }, { duration: prefersReducedMotion() ? 0 : 160 });
      }
    }
  }, [selectedNodeId]);

  useEffect(() => {
    if (prefersReducedMotion()) return undefined;
    let offset = 0;
    const timer = window.setInterval(() => {
      const cy = cyRef.current;
      if (!cy) return;
      const marching = cy.edges('.on-path');
      if (marching.length === 0) return;
      offset = (offset + MARCH_STEP_PX) % DASH_PERIOD_PX;
      marching.style('line-dash-offset', -offset);
    }, MARCH_INTERVAL_MS);
    return () => window.clearInterval(timer);
  }, []);

  return (
    <div className="cy-host">
      <div ref={hostRef} style={{ position: 'absolute', inset: 0 }} />
      {error ? (
        <div className="cy-overlay" style={{ pointerEvents: 'auto' }}>
          <ErrorBlock title="Map unavailable" message={error} onRetry={onRetry} />
        </div>
      ) : null}
      {!error && loading ? (
        <div className="cy-overlay">
          <Loading what="reading graph" />
        </div>
      ) : null}
      {!error && !loading && nodes.length === 0 ? (
        <div className="cy-overlay" style={{ pointerEvents: 'auto' }}>
          <EmptyState
            statement="Nothing on the map yet."
            detail="The map fills with the public ingress points, the services on the top attack paths and the crown jewels."
            action={emptyAction}
          />
        </div>
      ) : null}
    </div>
  );
}
