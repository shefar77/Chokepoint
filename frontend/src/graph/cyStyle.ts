/**
 * Cytoscape stylesheet. Cytoscape paints to canvas and cannot read CSS custom
 * properties, so every token is resolved to a concrete colour once and the
 * per-node glyph values travel in element data.
 */

import type { ElementDefinition, StylesheetStyle } from 'cytoscape';

import type { GraphEdge, GraphNode } from '../api/types';
import { glyphFor } from './glyphs';

const TOKEN = /var\(\s*(--[a-z0-9-]+)\s*\)/i;

let cache: Record<string, string> = {};

export function resolveToken(value: string): string {
  const match = TOKEN.exec(value);
  if (!match) return value;
  const name = match[1];
  if (cache[name]) return cache[name];
  const computed = getComputedStyle(document.documentElement).getPropertyValue(name).trim();
  const resolved = computed || '#16140f';
  cache = { ...cache, [name]: resolved };
  return resolved;
}

export const INK = () => resolveToken('var(--ink)');
export const INK_2 = () => resolveToken('var(--ink-2)');
export const INK_3 = () => resolveToken('var(--ink-3)');
export const PAPER = () => resolveToken('var(--paper)');
export const RULE_SOFT = () => resolveToken('var(--rule-soft)');
export const THREAT = () => resolveToken('var(--threat)');
export const SAFE = () => resolveToken('var(--safe)');
export const STRUCTURE = () => resolveToken('var(--structure)');

export function shortLabel(node: GraphNode): string {
  const raw = String(node.props.name ?? node.props.host ?? node.props.cve ?? node.id);
  return raw.length > 18 ? `${raw.slice(0, 17)}…` : raw;
}

export function edgeKey(edge: GraphEdge): string {
  return `${edge.source}|${edge.type}|${edge.target}`;
}

export function toElements(nodes: GraphNode[] | undefined, edges: GraphEdge[] | undefined): ElementDefinition[] {
  if (!nodes || !edges) return [];
  const present = new Set(nodes.map((node) => node.id));
  const elements: ElementDefinition[] = nodes.map((node) => {
    const spec = glyphFor(node.label, node.props);
    return {
      group: 'nodes',
      data: {
        id: node.id,
        label: node.label,
        short: shortLabel(node),
        full: String(node.props.name ?? node.id),
        shape: spec.shape,
        width: spec.width,
        height: spec.height,
        fill: resolveToken(spec.fill),
        border: resolveToken(spec.border),
        borderWidth: spec.borderWidth,
        borderStyle: spec.borderStyle,
      },
    };
  });
  for (const edge of edges) {
    if (!present.has(edge.source) || !present.has(edge.target)) continue;
    const authz = String(edge.props.authz ?? '');
    elements.push({
      group: 'edges',
      data: {
        id: edgeKey(edge),
        source: edge.source,
        target: edge.target,
        type: edge.type,
        authz,
      },
      classes: edge.type === 'CALLS' && (authz === 'none' || authz === '') ? 'unprotected' : undefined,
    });
  }
  return elements;
}

export function buildStylesheet(): StylesheetStyle[] {
  return [
    {
      selector: 'node',
      style: {
        shape: 'data(shape)',
        width: 'data(width)',
        height: 'data(height)',
        'background-color': 'data(fill)',
        'border-color': 'data(border)',
        'border-width': 'data(borderWidth)',
        'border-style': 'data(borderStyle)',
        label: 'data(short)',
        'font-family': 'IBM Plex Mono, monospace',
        'font-size': 10,
        color: INK_2(),
        'text-valign': 'bottom',
        'text-halign': 'center',
        'text-margin-y': 4,
        'text-opacity': 0,
        'text-background-color': PAPER(),
        'text-background-opacity': 0.85,
        'text-background-padding': '1px',
        'overlay-opacity': 0,
        'transition-property': 'none',
      },
    },
    { selector: 'node.labelled', style: { 'text-opacity': 1 } },
    {
      selector: 'node:selected',
      style: {
        'border-color': STRUCTURE(),
        'border-width': 3,
        'text-opacity': 1,
        color: INK(),
      },
    },
    {
      selector: 'node.highlighted',
      style: { 'border-color': STRUCTURE(), 'border-width': 3, 'text-opacity': 1 },
    },
    {
      selector: 'node.on-path',
      style: { 'border-color': THREAT(), 'border-width': 3, 'text-opacity': 1, color: INK() },
    },
    { selector: 'node.neighbour', style: { 'text-opacity': 1 } },
    { selector: '.dimmed', style: { opacity: 0.16 } },
    {
      selector: 'edge',
      style: {
        width: 1,
        'line-color': RULE_SOFT(),
        'curve-style': 'bezier',
        'control-point-step-size': 26,
        'target-arrow-shape': 'triangle',
        'target-arrow-color': RULE_SOFT(),
        'arrow-scale': 0.6,
        'overlay-opacity': 0,
      },
    },
    {
      selector: 'edge.unprotected',
      style: { 'line-style': 'dashed', 'line-dash-pattern': [4, 3], 'line-color': INK_3(), 'target-arrow-color': INK_3() },
    },
    {
      selector: 'edge.mitigated',
      style: { 'line-style': 'dotted', 'line-color': SAFE(), 'target-arrow-color': SAFE() },
    },
    {
      selector: 'edge.on-path',
      style: {
        width: 2.5,
        'line-color': THREAT(),
        'target-arrow-color': THREAT(),
        'line-style': 'dashed',
        'line-dash-pattern': [6, 4],
        'arrow-scale': 0.9,
        'z-index': 10,
      },
    },
    {
      selector: 'edge.neighbour',
      style: { 'line-color': INK_2(), 'target-arrow-color': INK_2() },
    },
  ] as StylesheetStyle[];
}
