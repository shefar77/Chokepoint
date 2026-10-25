/**
 * The map legend, hand-set. `MiniGlyph` draws the same glyph vocabulary the
 * Cytoscape stylesheet uses, so the legend cannot drift from the map.
 */

import type { ReactElement } from 'react';

import { glyphFor, LEGEND_EDGES, LEGEND_NODES, type GlyphSpec } from '../graph/glyphs';

const BOX = 16;

function shapePath(spec: GlyphSpec): ReactElement {
  const w = Math.min(spec.width, 13);
  const h = Math.min(spec.height, 13);
  const cx = BOX / 2;
  const cy = BOX / 2;
  const common = {
    fill: spec.fill,
    stroke: spec.border,
    strokeWidth: Math.min(spec.borderWidth, 2),
    strokeDasharray: spec.borderStyle === 'dashed' ? '2 2' : undefined,
  };
  switch (spec.shape) {
    case 'ellipse':
      return <circle cx={cx} cy={cy} r={w / 2} {...common} />;
    case 'diamond':
      return (
        <polygon
          points={`${cx},${cy - h / 2} ${cx + w / 2},${cy} ${cx},${cy + h / 2} ${cx - w / 2},${cy}`}
          {...common}
        />
      );
    case 'triangle':
      return (
        <polygon
          points={`${cx},${cy - h / 2} ${cx + w / 2},${cy + h / 2} ${cx - w / 2},${cy + h / 2}`}
          {...common}
        />
      );
    case 'hexagon':
      return (
        <polygon
          points={`${cx - w / 4},${cy - h / 2} ${cx + w / 4},${cy - h / 2} ${cx + w / 2},${cy} ${
            cx + w / 4
          },${cy + h / 2} ${cx - w / 4},${cy + h / 2} ${cx - w / 2},${cy}`}
          {...common}
        />
      );
    case 'round-rectangle':
      return <rect x={cx - w / 2} y={cy - h / 2} width={w} height={h} rx={2} {...common} />;
    default:
      return <rect x={cx - w / 2} y={cy - h / 2} width={w} height={h} {...common} />;
  }
}

export function MiniGlyph({
  label,
  props = {},
  size = 16,
  title,
}: {
  label: string;
  props?: Record<string, unknown>;
  size?: number;
  title?: string;
}) {
  const spec = glyphFor(label, props);
  return (
    <svg
      width={size}
      height={size}
      viewBox={`0 0 ${BOX} ${BOX}`}
      role={title ? 'img' : 'presentation'}
      aria-hidden={title ? undefined : true}
      aria-label={title}
      style={{ display: 'block', flex: 'none' }}
      focusable="false"
    >
      {title ? <title>{title}</title> : null}
      {spec.borderStyle === 'double' ? (
        <circle
          cx={BOX / 2}
          cy={BOX / 2}
          r={4}
          fill="none"
          stroke={spec.border}
          strokeWidth={1.2}
        />
      ) : null}
      {spec.borderStyle === 'double' ? (
        <circle cx={BOX / 2} cy={BOX / 2} r={6.5} fill="none" stroke={spec.border} strokeWidth={1.2} />
      ) : (
        shapePath(spec)
      )}
    </svg>
  );
}

function EdgeSample({ kind }: { kind: 'plain' | 'unprotected' | 'path' | 'mitigated' }) {
  const stroke =
    kind === 'path' ? 'var(--threat)' : kind === 'mitigated' ? 'var(--safe)' : 'var(--rule-soft)';
  const dash = kind === 'unprotected' ? '3 2' : kind === 'mitigated' ? '1 3' : undefined;
  return (
    <svg width={22} height={10} viewBox="0 0 22 10" aria-hidden="true" focusable="false" style={{ display: 'block' }}>
      <line
        x1="1"
        y1="5"
        x2="21"
        y2="5"
        stroke={stroke}
        strokeWidth={kind === 'path' ? 2.5 : 1}
        strokeDasharray={dash}
      />
    </svg>
  );
}

export function Legend() {
  return (
    <div className="legend" aria-label="Map legend">
      <div className="legend-group">
        {LEGEND_NODES.map((item) => (
          <span className="legend-item" key={item.label}>
            <MiniGlyph label={item.kind} props={item.props} />
            {item.label}
          </span>
        ))}
      </div>
      <div className="legend-group">
        {LEGEND_EDGES.map((item) => (
          <span className="legend-item" key={item.label}>
            <EdgeSample kind={item.kind} />
            {item.label}
          </span>
        ))}
      </div>
    </div>
  );
}
