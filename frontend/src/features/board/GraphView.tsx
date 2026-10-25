/** "The graph's view": full attack graph with all paths. */

import { Link } from 'react-router-dom';

import type { AttackPathModel, InvestigationSummary } from '../../api/types';
import { EmptyState } from '../../components/EmptyState';
import { Loading } from '../../components/Loading';
import { Panel } from '../../components/Panel';
import { Button } from '../../components/Button';
import { useEffect, useState } from 'react';
import { score } from '../../lib/format';

interface BoardGraphViewProps {
  paths: AttackPathModel[];
  latest: InvestigationSummary | null;
  loading: boolean;
  onStart: () => void;
}

export function BoardGraphView({ paths, latest, loading, onStart }: BoardGraphViewProps) {
  const [showFullGraph, setShowFullGraph] = useState(false);

  useEffect(() => {
    // Always show full graph when paths are available
    if (paths.length > 0) {
      setShowFullGraph(true);
    }
  }, [paths]);

  if (!showFullGraph || loading) {
    return (
      <Panel
        number="02"
        title="The graph's view"
        right={
          latest ? (
            <Link to={`/i/${latest.id}`} className="mono-sm">
              {latest.id}
            </Link>
          ) : null
        }
        flush
      >
        <div style={{ padding: 'var(--s-3) var(--s-3) 0' }}>
          <p className="mono-sm" style={{ margin: 0 }}>
            Paths from the open internet to a crown jewel, ordered by what they would actually cost you.
          </p>
        </div>
        {loading ? (
          <div style={{ padding: 'var(--s-3)' }}>
            <Loading what="reading paths" />
          </div>
        ) : paths.length === 0 ? (
          <div style={{ padding: 'var(--s-3)' }}>
            <EmptyState
              statement="No investigation has mapped the estate yet."
              detail="An investigation enumerates every internet-to-crown-jewel path, scores it, and names the smallest set of fixes that cuts the most risk."
              action={
                <Button variant="primary" icon="play" onClick={onStart}>
                  Triage the latest scan
                </Button>
              }
            />
          </div>
        ) : (
          <div className="path-list">
            {paths.slice(0, 8).map((path, idx) => (
              <Link key={path.id} to={latest ? `/i/${latest.id}` : '/'} className="path-row" style={{ borderBottom: idx < 7 ? '1px solid var(--rule-soft)' : 'none', margin: 'var(--s-3) 0' }}>
                <span className="path-chain">{path.nodes.map((node) => node.id).join(' → ')}</span>
                <span className="path-meta">
                  <span className="ribbon-score">{score(path.score_pct)}</span>
                  {' · '}
                  {path.hops} hops
                </span>
              </Link>
            ))}
          </div>
        )}
      </Panel>
    );
  }

  // Show full graph when we have data
  const totalPaths = paths.length;
  const displayedPaths = paths.slice(0, 20); // Show up to 20 in full view

  return (
    <Panel
      number="02"
      title="The full security graph"
      right={
        latest ? (
          <Link to={`/i/${latest.id}`} className="mono-sm">
            {latest.id}
          </Link>
        ) : null
      }
      flush
    >
      <div style={{ padding: 'var(--s-3) var(--s-3) 0' }}>
        <p className="mono-sm" style={{ margin: 0 }}>
          Full attack graph: {totalPaths} paths from internet to crown jewels
        </p>
      </div>
      <div style={{ padding: 'var(--s-3)' }}>
        <Button
          variant="quiet"
          icon="reset"
          style={{ margin: 'var(--s-3) 0 0' }}
          onClick={() => setShowFullGraph(false)}
        >
          Hide graph / Show top paths
        </Button>
        <p className="mono-sm" style={{ margin: 'var(--s-3) 0 0' }}>
          Showing {displayedPaths.length} of {totalPaths} paths
        </p>
      </div>
      <div style={{ padding: 'var(--s-3)' }}>
        <div className="path-list">
          {displayedPaths.map((path, idx) => (
            <div key={path.id} style={{ borderBottom: idx < displayedPaths.length - 1 ? '1px solid var(--rule-soft)' : 'none', margin: 'var(--s-3) 0' }}>
              <span className="path-chain">{path.nodes.map((node) => node.id).join(' → ')}</span>
              <span className="path-meta">
                <span className="ribbon-score">{score(path.score_pct)}</span>
                {' · '}
                {path.hops} hops
              </span>
            </div>
          ))}
        </div>
        {totalPaths > displayedPaths.length && (
          <p className="mono-xs" style={{ margin: 'var(--s-3) 0 0', color: 'var(--rule-soft)' }}>
            {totalPaths - displayedPaths.length} more paths not shown
          </p>
        )}
      </div>
    </Panel>
  );
}