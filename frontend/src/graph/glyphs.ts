/**
 * Node glyphs: shape and fill carry the type, nothing is drawn inside a node.
 * The same specs drive the Cytoscape stylesheet and the hand-set legend.
 */

export type NodeKind =
  | 'Internet'
  | 'Ingress'
  | 'Service'
  | 'DataStore'
  | 'Package'
  | 'Vulnerability'
  | 'Finding'
  | 'Control'
  | 'IAMRole'
  | 'Team'
  | 'Person'
  | 'Unknown';

export type CyShape =
  | 'ellipse'
  | 'diamond'
  | 'rectangle'
  | 'round-rectangle'
  | 'triangle'
  | 'hexagon';

export interface GlyphSpec {
  shape: CyShape;
  width: number;
  height: number;
  fill: string;
  border: string;
  borderWidth: number;
  borderStyle: 'solid' | 'double' | 'dashed';
}

export const CLASSIFICATION_FILL: Record<string, string> = {
  pci: 'var(--ink)',
  secrets: 'var(--ink)',
  pii: 'var(--structure)',
  internal: 'var(--paper-3)',
  public: 'var(--paper-3)',
};

const SERVICE_SIZE: Record<number, number> = { 1: 26, 2: 20, 3: 15 };

const BASE: Record<NodeKind, GlyphSpec> = {
  Internet: {
    shape: 'ellipse',
    width: 26,
    height: 26,
    fill: 'var(--paper)',
    border: 'var(--ink)',
    borderWidth: 3,
    borderStyle: 'double',
  },
  Ingress: {
    shape: 'diamond',
    width: 20,
    height: 20,
    fill: 'var(--paper)',
    border: 'var(--ink)',
    borderWidth: 1.5,
    borderStyle: 'solid',
  },
  Service: {
    shape: 'ellipse',
    width: 20,
    height: 20,
    fill: 'var(--paper)',
    border: 'var(--ink)',
    borderWidth: 1.5,
    borderStyle: 'solid',
  },
  DataStore: {
    shape: 'rectangle',
    width: 22,
    height: 22,
    fill: 'var(--paper-3)',
    border: 'var(--ink)',
    borderWidth: 1.5,
    borderStyle: 'solid',
  },
  Package: {
    shape: 'triangle',
    width: 14,
    height: 13,
    fill: 'var(--paper)',
    border: 'var(--ink-2)',
    borderWidth: 1.5,
    borderStyle: 'solid',
  },
  Vulnerability: {
    shape: 'triangle',
    width: 12,
    height: 11,
    fill: 'var(--threat)',
    border: 'var(--threat)',
    borderWidth: 1,
    borderStyle: 'solid',
  },
  Finding: {
    shape: 'rectangle',
    width: 10,
    height: 10,
    fill: 'var(--paper)',
    border: 'var(--threat)',
    borderWidth: 1.5,
    borderStyle: 'solid',
  },
  Control: {
    shape: 'hexagon',
    width: 20,
    height: 18,
    fill: 'var(--safe)',
    border: 'var(--safe)',
    borderWidth: 1.5,
    borderStyle: 'solid',
  },
  IAMRole: {
    shape: 'round-rectangle',
    width: 20,
    height: 12,
    fill: 'var(--paper)',
    border: 'var(--ink-2)',
    borderWidth: 1.5,
    borderStyle: 'solid',
  },
  Team: {
    shape: 'round-rectangle',
    width: 18,
    height: 12,
    fill: 'var(--paper-2)',
    border: 'var(--ink-3)',
    borderWidth: 1,
    borderStyle: 'solid',
  },
  Person: {
    shape: 'ellipse',
    width: 12,
    height: 12,
    fill: 'var(--paper-2)',
    border: 'var(--ink-3)',
    borderWidth: 1,
    borderStyle: 'solid',
  },
  Unknown: {
    shape: 'ellipse',
    width: 14,
    height: 14,
    fill: 'var(--paper-2)',
    border: 'var(--ink-3)',
    borderWidth: 1,
    borderStyle: 'dashed',
  },
};

export function asKind(label: string): NodeKind {
  return (Object.keys(BASE) as NodeKind[]).includes(label as NodeKind)
    ? (label as NodeKind)
    : 'Unknown';
}

export function glyphFor(label: string, props: Record<string, unknown> = {}): GlyphSpec {
  const kind = asKind(label);
  const spec = { ...BASE[kind] };
  if (kind === 'Service') {
    const tier = Number(props.tier ?? 2);
    const size = SERVICE_SIZE[tier] ?? 20;
    spec.width = size;
    spec.height = size;
    const status = String(props.status ?? 'active');
    if (status !== 'active') {
      spec.borderStyle = 'dashed';
      spec.border = 'var(--ink-3)';
    }
    if (props.internet_facing === true) {
      spec.borderWidth = 2.5;
    }
  }
  if (kind === 'DataStore') {
    const classification = String(props.classification ?? 'internal');
    spec.fill = CLASSIFICATION_FILL[classification] ?? 'var(--paper-3)';
    if (props.crown_jewel === true) spec.borderWidth = 2.5;
  }
  if (kind === 'Ingress' && props.public !== true) {
    spec.borderStyle = 'dashed';
    spec.border = 'var(--ink-3)';
  }
  if (kind === 'Control' && props.active !== true) {
    spec.fill = 'var(--paper)';
    spec.border = 'var(--ink-3)';
    spec.borderStyle = 'dashed';
  }
  return spec;
}

/** Order used by the legend and the layout's left-to-right ranks. */
export const RANK: Record<NodeKind, number> = {
  Internet: 0,
  Ingress: 1,
  Service: 2,
  Package: 3,
  Vulnerability: 3,
  Finding: 3,
  Control: 2,
  IAMRole: 4,
  DataStore: 5,
  Team: 1,
  Person: 1,
  Unknown: 3,
};

export const LEGEND_NODES: { label: string; kind: NodeKind; props?: Record<string, unknown> }[] = [
  { label: 'internet', kind: 'Internet' },
  { label: 'ingress', kind: 'Ingress', props: { public: true } },
  { label: 'service', kind: 'Service', props: { tier: 2 } },
  { label: 'pci / secrets', kind: 'DataStore', props: { classification: 'pci', crown_jewel: true } },
  { label: 'pii', kind: 'DataStore', props: { classification: 'pii', crown_jewel: true } },
  { label: 'other data', kind: 'DataStore', props: { classification: 'internal' } },
  { label: 'iam role', kind: 'IAMRole' },
  { label: 'package', kind: 'Package' },
  { label: 'vulnerability', kind: 'Vulnerability' },
  { label: 'control', kind: 'Control', props: { active: true } },
];

export const LEGEND_EDGES: { label: string; kind: 'plain' | 'unprotected' | 'path' | 'mitigated' }[] = [
  { label: 'edge', kind: 'plain' },
  { label: 'calls, no authz', kind: 'unprotected' },
  { label: 'attack path', kind: 'path' },
  { label: 'mitigated', kind: 'mitigated' },
];
