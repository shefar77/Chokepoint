/**
 * The path ribbon: every attack path as a horizontal run of glyphs with its
 * score. Selecting one dims the rest of the map.
 */

import type { AttackPathModel } from '../api/types';
import { MiniGlyph } from '../components/Legend';
import { score } from '../lib/format';

interface PathRibbonProps {
  paths: AttackPathModel[];
  selectedId: string | null;
  onSelect: (path: AttackPathModel | null) => void;
}

export function PathRibbon({ paths, selectedId, onSelect }: PathRibbonProps) {
  if (paths.length === 0) {
    return (
      <div className="ribbon">
        <span className="mono-sm">
          No internet-to-crown-jewel path on the board yet. Run an investigation to enumerate them.
        </span>
      </div>
    );
  }
  return (
    <div className="ribbon" aria-label="Attack paths">
      <div className="ribbon-track">
        {paths.map((path) => {
          const selected = path.id === selectedId;
          return (
            <button
              key={path.id}
              type="button"
              className="ribbon-item"
              aria-pressed={selected}
              onClick={() => onSelect(selected ? null : path)}
              title={`${path.nodes.map((node) => node.id).join(' -> ')} · ${path.hops} hops · entry authn ${
                path.entry_authn || 'unknown'
              }`}
            >
              <span className="ribbon-glyphs">
                {path.nodes.map((node, index) => (
                  <span key={`${path.id}-${node.id}-${index}`} className="ribbon-glyphs">
                    {index > 0 ? <span className="ribbon-sep" /> : null}
                    <MiniGlyph label={node.label} size={13} />
                  </span>
                ))}
              </span>
              <span className="ribbon-foot">
                <span className="ribbon-label">
                  {path.entry} → {path.target}
                </span>
                <span className="ribbon-score">{score(path.score_pct)}</span>
              </span>
              <span className="mono-sm">
                {path.hops} hops · authn {path.entry_authn || '—'}
              </span>
            </button>
          );
        })}
      </div>
    </div>
  );
}
